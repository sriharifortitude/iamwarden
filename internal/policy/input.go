package policy

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Named is a policy document with where it came from.
type Named struct {
	// Name is the policy's name, or a description such as "inline policy deploy".
	Name string
	Doc  *Document
}

// Subject is something that holds permissions: a user, a group, a role, or a lone policy
// file. Its Identity policies are judged together, as AWS evaluates them together.
type Subject struct {
	Kind     string // "user", "group", "role", "policy" or "resource policy"
	Name     string
	Arn      string
	Identity []Named
	// Trust is a role's trust policy.
	Trust *Document
	// Resource holds resource policies (a bucket policy, a key policy).
	Resource []Named
}

// Input is everything read from one file.
type Input struct {
	Subjects []Subject
	// Problems are documents that could not be read, by where they were.
	Problems []string
}

type authDetails struct {
	UserDetailList []struct {
		UserName                string     `json:"UserName"`
		Arn                     string     `json:"Arn"`
		GroupList               []string   `json:"GroupList"`
		UserPolicyList          []inline   `json:"UserPolicyList"`
		AttachedManagedPolicies []attached `json:"AttachedManagedPolicies"`
	} `json:"UserDetailList"`
	GroupDetailList []struct {
		GroupName               string     `json:"GroupName"`
		Arn                     string     `json:"Arn"`
		GroupPolicyList         []inline   `json:"GroupPolicyList"`
		AttachedManagedPolicies []attached `json:"AttachedManagedPolicies"`
	} `json:"GroupDetailList"`
	RoleDetailList []struct {
		RoleName                 string          `json:"RoleName"`
		Arn                      string          `json:"Arn"`
		AssumeRolePolicyDocument json.RawMessage `json:"AssumeRolePolicyDocument"`
		RolePolicyList           []inline        `json:"RolePolicyList"`
		AttachedManagedPolicies  []attached      `json:"AttachedManagedPolicies"`
	} `json:"RoleDetailList"`
	Policies []struct {
		PolicyName        string `json:"PolicyName"`
		Arn               string `json:"Arn"`
		DefaultVersionID  string `json:"DefaultVersionId"`
		PolicyVersionList []struct {
			Document         json.RawMessage `json:"Document"`
			VersionID        string          `json:"VersionId"`
			IsDefaultVersion bool            `json:"IsDefaultVersion"`
		} `json:"PolicyVersionList"`
	} `json:"Policies"`
}

type inline struct {
	PolicyName     string          `json:"PolicyName"`
	PolicyDocument json.RawMessage `json:"PolicyDocument"`
}

type attached struct {
	PolicyName string `json:"PolicyName"`
	PolicyArn  string `json:"PolicyArn"`
}

// Read recognises a policy document, the output of `aws iam get-account-authorization-details`,
// or the wrappers the AWS CLI puts around single documents (get-policy-version, get-role,
// get-bucket-policy, get-key-policy).
func Read(name string, data []byte) (*Input, error) {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, fmt.Errorf("%s: not JSON: %v", name, err)
	}
	in := &Input{}
	switch {
	case probe["UserDetailList"] != nil || probe["RoleDetailList"] != nil || probe["Policies"] != nil:
		var a authDetails
		if err := json.Unmarshal(data, &a); err != nil {
			return nil, fmt.Errorf("%s: %v", name, err)
		}
		in.fromAuthDetails(a)
	case probe["Statement"] != nil:
		in.lone(name, data)
	case probe["PolicyVersion"] != nil:
		var w struct {
			PolicyVersion struct {
				Document json.RawMessage `json:"Document"`
			} `json:"PolicyVersion"`
		}
		_ = json.Unmarshal(data, &w)
		in.lone(name, w.PolicyVersion.Document)
	case probe["Role"] != nil:
		var w struct {
			Role struct {
				RoleName                 string          `json:"RoleName"`
				Arn                      string          `json:"Arn"`
				AssumeRolePolicyDocument json.RawMessage `json:"AssumeRolePolicyDocument"`
			} `json:"Role"`
		}
		_ = json.Unmarshal(data, &w)
		s := Subject{Kind: "role", Name: w.Role.RoleName, Arn: w.Role.Arn}
		s.Trust = in.parse(w.Role.AssumeRolePolicyDocument, "role "+w.Role.RoleName+" trust policy")
		in.Subjects = append(in.Subjects, s)
	case probe["Policy"] != nil:
		var w struct {
			Policy json.RawMessage `json:"Policy"`
		}
		_ = json.Unmarshal(data, &w)
		in.lone(name, w.Policy)
	default:
		return nil, fmt.Errorf("%s: neither a policy document nor get-account-authorization-details output", name)
	}
	return in, nil
}

func (in *Input) parse(raw json.RawMessage, where string) *Document {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	doc, err := Parse(raw)
	if err != nil {
		in.Problems = append(in.Problems, where+": "+err.Error())
		return nil
	}
	return doc
}

// lone handles a single document: a resource policy if any statement names a principal,
// otherwise an identity policy.
func (in *Input) lone(name string, raw json.RawMessage) {
	doc := in.parse(raw, name)
	if doc == nil {
		return
	}
	for _, st := range doc.Statements {
		if st.Principal != nil || st.NotPrincipal != nil {
			if isTrust(doc) {
				in.Subjects = append(in.Subjects, Subject{Kind: "role", Name: name, Trust: doc})
			} else {
				in.Subjects = append(in.Subjects, Subject{Kind: "resource policy", Name: name, Resource: []Named{{name, doc}}})
			}
			return
		}
	}
	in.Subjects = append(in.Subjects, Subject{Kind: "policy", Name: name, Identity: []Named{{name, doc}}})
}

// isTrust reports a role trust policy: every statement is about assuming a role.
func isTrust(d *Document) bool {
	for _, st := range d.Statements {
		for _, a := range append(append([]string{}, st.Action...), st.NotAction...) {
			if !strings.HasPrefix(strings.ToLower(a), "sts:") {
				return false
			}
		}
	}
	return true
}

func (in *Input) fromAuthDetails(a authDetails) {
	managed := map[string]Named{}
	for _, p := range a.Policies {
		for _, v := range p.PolicyVersionList {
			if v.IsDefaultVersion || v.VersionID == p.DefaultVersionID {
				if doc := in.parse(v.Document, "managed policy "+p.PolicyName); doc != nil {
					managed[p.Arn] = Named{p.PolicyName, doc}
				}
				break
			}
		}
	}
	attach := func(owner string, list []attached) []Named {
		var out []Named
		for _, at := range list {
			if n, ok := managed[at.PolicyArn]; ok {
				out = append(out, n)
			} else {
				in.Problems = append(in.Problems, fmt.Sprintf("%s: attached policy %s (%s) is not in the file, so it was not judged",
					owner, at.PolicyName, at.PolicyArn))
			}
		}
		return out
	}
	inlines := func(owner string, list []inline) []Named {
		var out []Named
		for _, p := range list {
			if doc := in.parse(p.PolicyDocument, owner+" inline policy "+p.PolicyName); doc != nil {
				out = append(out, Named{"inline " + p.PolicyName, doc})
			}
		}
		return out
	}
	groups := map[string][]Named{}
	for _, g := range a.GroupDetailList {
		owner := "group " + g.GroupName
		ps := append(inlines(owner, g.GroupPolicyList), attach(owner, g.AttachedManagedPolicies)...)
		groups[g.GroupName] = ps
		in.Subjects = append(in.Subjects, Subject{Kind: "group", Name: g.GroupName, Arn: g.Arn, Identity: ps})
	}
	for _, u := range a.UserDetailList {
		owner := "user " + u.UserName
		ps := append(inlines(owner, u.UserPolicyList), attach(owner, u.AttachedManagedPolicies)...)
		for _, g := range u.GroupList {
			for _, n := range groups[g] {
				ps = append(ps, Named{n.Name + " (through group " + g + ")", n.Doc})
			}
		}
		in.Subjects = append(in.Subjects, Subject{Kind: "user", Name: u.UserName, Arn: u.Arn, Identity: ps})
	}
	for _, r := range a.RoleDetailList {
		owner := "role " + r.RoleName
		s := Subject{Kind: "role", Name: r.RoleName, Arn: r.Arn,
			Identity: append(inlines(owner, r.RolePolicyList), attach(owner, r.AttachedManagedPolicies)...)}
		s.Trust = in.parse(r.AssumeRolePolicyDocument, owner+" trust policy")
		in.Subjects = append(in.Subjects, s)
	}
	sort.Strings(in.Problems)
}

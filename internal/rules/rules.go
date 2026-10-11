// Package rules judges what an IAM subject can do, and who can reach a role or a resource.
package rules

import (
	"fmt"
	"sort"
	"strings"

	"github.com/sriharifortitude/iamwarden/internal/policy"
)

// Severities, most serious first.
var Severities = []string{"critical", "high", "medium", "low", "info"}

// Rank orders severities: critical is 0.
func Rank(s string) int {
	for i, v := range Severities {
		if v == s {
			return i
		}
	}
	return len(Severities)
}

// Finding is one problem with one subject.
type Finding struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	// Subject is "user alice", "role deploy", "policy file.json".
	Subject string `json:"subject"`
	// Policies names the policies (and statements) responsible.
	Policies []string `json:"policies,omitempty"`
	Message  string   `json:"message"`
}

// grant is how a subject holds one action.
type grant struct {
	anyResource bool
	conditional bool
	from        []string
}

// granted works out, for one action, whether the subject's identity policies allow it, on what,
// and from which statements. An unconditional Deny on every resource removes it.
func granted(s policy.Subject, action string) *grant { return grantedTo(s, action, "") }

// grantedTo is granted for iam:PassRole when the role must be passed to a particular service:
// a statement whose iam:PassedToService condition names other services does not count.
func grantedTo(s policy.Subject, action, service string) *grant {
	var g *grant
	for _, n := range s.Identity {
		for _, st := range n.Doc.Statements {
			if st.Effect == "Deny" && st.Condition == nil && st.AnyResource() && st.Allows(action) {
				return nil
			}
		}
	}
	for _, n := range s.Identity {
		for _, st := range n.Doc.Statements {
			if st.Effect != "Allow" || !st.Allows(action) {
				continue
			}
			if service != "" && !passesTo(st, service) {
				continue
			}
			if g == nil {
				g = &grant{conditional: true}
			}
			g.anyResource = g.anyResource || st.AnyResource()
			g.conditional = g.conditional && conditionedBeyond(st, service)
			g.from = appendNew(g.from, label(n, st))
		}
	}
	return g
}

// conditionedBeyond reports conditions that limit a grant. When the role is being passed to a
// service, an iam:PassedToService condition that names that service limits nothing.
func conditionedBeyond(st policy.Statement, service string) bool {
	for _, k := range st.ConditionKeys() {
		if service == "" || k != "iam:passedtoservice" {
			return true
		}
	}
	return false
}

// passesTo reports whether a PassRole statement lets a role be passed to service.
func passesTo(st policy.Statement, service string) bool {
	allowed := st.ConditionValues("iam:PassedToService")
	if len(allowed) == 0 {
		return true
	}
	for _, v := range allowed {
		if policy.MatchAction(v, service) {
			return true
		}
	}
	return false
}

func label(n policy.Named, st policy.Statement) string {
	if st.Sid != "" {
		return fmt.Sprintf("%s (%s)", n.Name, st.Sid)
	}
	if len(n.Doc.Statements) > 1 {
		return fmt.Sprintf("%s (statement %d)", n.Name, st.Index+1)
	}
	return n.Name
}

func appendNew(list []string, add ...string) []string {
	for _, a := range add {
		dup := false
		for _, b := range list {
			if a == b {
				dup = true
				break
			}
		}
		if !dup {
			list = append(list, a)
		}
	}
	return list
}

// escalation is one known way to turn limited IAM permissions into more.
type escalation struct {
	actions []string
	how     string
	// passTo is the service principal the role is passed to, for methods that use iam:PassRole.
	passTo string
}

// escalations are the privilege-escalation methods published by Rhino Security Labs
// ("AWS IAM Privilege Escalation - Methods and Mitigation", 2018) and later write-ups. Each
// needs every listed action.
var escalations = []escalation{
	{[]string{"iam:CreatePolicyVersion"}, "write a new default version of a policy attached to itself", ""},
	{[]string{"iam:SetDefaultPolicyVersion"}, "switch a policy attached to itself to an older, broader version", ""},
	{[]string{"iam:CreateAccessKey"}, "create access keys for another user", ""},
	{[]string{"iam:CreateLoginProfile"}, "give another user a console password", ""},
	{[]string{"iam:UpdateLoginProfile"}, "reset another user's console password", ""},
	{[]string{"iam:AttachUserPolicy"}, "attach AdministratorAccess to a user", ""},
	{[]string{"iam:AttachGroupPolicy"}, "attach AdministratorAccess to a group it is in", ""},
	{[]string{"iam:AttachRolePolicy", "sts:AssumeRole"}, "attach AdministratorAccess to a role and assume it", ""},
	{[]string{"iam:PutUserPolicy"}, "write an inline admin policy on a user", ""},
	{[]string{"iam:PutGroupPolicy"}, "write an inline admin policy on a group it is in", ""},
	{[]string{"iam:PutRolePolicy", "sts:AssumeRole"}, "write an inline admin policy on a role and assume it", ""},
	{[]string{"iam:AddUserToGroup"}, "add itself to an administrators group", ""},
	{[]string{"iam:UpdateAssumeRolePolicy", "sts:AssumeRole"}, "make a privileged role trust it, then assume it", ""},
	{[]string{"iam:PassRole", "ec2:RunInstances"}, "start an instance with a privileged role and read its credentials", "ec2.amazonaws.com"},
	{[]string{"iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"}, "create and run a Lambda function with a privileged role", "lambda.amazonaws.com"},
	{[]string{"iam:PassRole", "lambda:CreateFunction", "lambda:CreateEventSourceMapping"}, "create a Lambda function with a privileged role and trigger it from a stream", "lambda.amazonaws.com"},
	{[]string{"lambda:UpdateFunctionCode"}, "replace the code of a function that has a privileged role", ""},
	{[]string{"iam:PassRole", "glue:CreateDevEndpoint"}, "create a Glue endpoint with a privileged role and log in to it", "glue.amazonaws.com"},
	{[]string{"glue:UpdateDevEndpoint"}, "add its SSH key to a Glue endpoint that has a privileged role", ""},
	{[]string{"iam:PassRole", "cloudformation:CreateStack"}, "create a CloudFormation stack that runs as a privileged role", "cloudformation.amazonaws.com"},
	{[]string{"iam:PassRole", "datapipeline:CreatePipeline", "datapipeline:PutPipelineDefinition"}, "run a Data Pipeline as a privileged role", "datapipeline.amazonaws.com"},
	{[]string{"iam:PassRole", "ecs:RegisterTaskDefinition", "ecs:RunTask"}, "run an ECS task with a privileged role", "ecs-tasks.amazonaws.com"},
	{[]string{"iam:PassRole", "codebuild:CreateProject", "codebuild:StartBuild"}, "run a CodeBuild build as a privileged role", "codebuild.amazonaws.com"},
	{[]string{"iam:PassRole", "sagemaker:CreateNotebookInstance", "sagemaker:CreatePresignedNotebookInstanceUrl"}, "open a SageMaker notebook with a privileged role", "sagemaker.amazonaws.com"},
	{[]string{"ssm:SendCommand"}, "run commands on any managed instance, as root, with that instance's role", ""},
}

var secretReads = []string{"secretsmanager:GetSecretValue", "ssm:GetParameter", "ssm:GetParameters", "ssm:GetParametersByPath", "kms:Decrypt"}

// Check judges every subject.
func Check(in *policy.Input) []Finding {
	var out []Finding
	for _, p := range in.Problems {
		out = append(out, Finding{ID: "IAM090", Severity: "info", Subject: "input", Message: p})
	}
	for _, s := range in.Subjects {
		who := s.Kind + " " + s.Name
		if len(s.Identity) > 0 {
			out = append(out, identity(who, s)...)
			out = append(out, statementShape(who, s.Identity)...)
		}
		if s.Trust != nil {
			out = append(out, trust(who, s)...)
			out = append(out, statementShape(who, []policy.Named{{Name: "trust policy", Doc: s.Trust}})...)
		}
		for _, r := range s.Resource {
			out = append(out, resource(who, r)...)
			out = append(out, statementShape(who, []policy.Named{r})...)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Subject != out[j].Subject {
			return out[i].Subject < out[j].Subject
		}
		if Rank(out[i].Severity) != Rank(out[j].Severity) {
			return Rank(out[i].Severity) < Rank(out[j].Severity)
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func severity(g *grant, base string) string {
	if !g.anyResource {
		base = lower(base)
	}
	if g.conditional {
		base = lower(base)
	}
	return base
}

func lower(s string) string {
	if i := Rank(s); i+1 < len(Severities) {
		return Severities[i+1]
	}
	return s
}

func scope(g *grant) string {
	var parts []string
	if !g.anyResource {
		parts = append(parts, "on the resources the policy names")
	}
	if g.conditional {
		parts = append(parts, "when the policy's conditions hold")
	}
	if len(parts) == 0 {
		return ""
	}
	return " (" + strings.Join(parts, ", ") + ")"
}

func identity(who string, s policy.Subject) []Finding {
	var out []Finding
	// Administrator: every action on every resource. Everything below is implied by it.
	if g := granted(s, "iam:CreatePolicyVersion"); g != nil && g.anyResource && everything(s) {
		return []Finding{{ID: "IAM001", Severity: severity(g, "critical"), Subject: who, Policies: g.from,
			Message: "has every action on every resource: an administrator" + scope(g)}}
	}
	for _, e := range escalations {
		var all []string
		ok, anyRes, cond := true, true, false
		for _, a := range e.actions {
			g := granted(s, a)
			if a == "iam:PassRole" {
				g = grantedTo(s, a, e.passTo)
			}
			if g == nil {
				ok = false
				break
			}
			anyRes = anyRes && g.anyResource
			cond = cond || g.conditional
			all = appendNew(all, g.from...)
		}
		if !ok {
			continue
		}
		g := &grant{anyResource: anyRes, conditional: cond}
		out = append(out, Finding{ID: "IAM002", Severity: severity(g, "high"), Subject: who, Policies: all,
			Message: fmt.Sprintf("can escalate its privileges: with %s it can %s%s", strings.Join(e.actions, " + "), e.how, scope(g))})
	}
	for _, a := range secretReads {
		if g := granted(s, a); g != nil && g.anyResource {
			out = append(out, Finding{ID: "IAM004", Severity: "medium", Subject: who, Policies: g.from,
				Message: fmt.Sprintf("can call %s on every resource: every secret it protects is readable%s", a, scope(g))})
		}
	}
	for _, n := range s.Identity {
		for _, st := range n.Doc.Statements {
			if st.Effect != "Allow" {
				continue
			}
			if st.NotAction != nil {
				out = append(out, Finding{ID: "IAM003", Severity: "medium", Subject: who, Policies: []string{label(n, st)},
					Message: fmt.Sprintf("allows NotAction %s: every other action of every service, including services AWS has not launched yet", strings.Join(st.NotAction, ", "))})
			}
			if st.NotResource != nil {
				out = append(out, Finding{ID: "IAM003", Severity: "medium", Subject: who, Policies: []string{label(n, st)},
					Message: fmt.Sprintf("allows its actions on NotResource %s: every other resource, including ones created later", strings.Join(st.NotResource, ", "))})
			}
			if st.AnyResource() {
				for _, a := range st.Action {
					if svc, rest, ok := strings.Cut(a, ":"); ok && rest == "*" && !strings.EqualFold(svc, "iam") {
						out = append(out, Finding{ID: "IAM005", Severity: "medium", Subject: who, Policies: []string{label(n, st)},
							Message: fmt.Sprintf("allows %s on every resource: full control of every %s resource in the account", a, svc)})
					}
				}
			}
		}
	}
	return dedupe(out)
}

// everything reports a statement that allows all actions on all resources.
func everything(s policy.Subject) bool {
	for _, n := range s.Identity {
		for _, st := range n.Doc.Statements {
			if st.Effect == "Allow" && st.AnyResource() && st.Allows("zzz:Unlisted") && st.Allows("iam:PassRole") && st.Allows("s3:GetObject") {
				return true
			}
		}
	}
	return false
}

func dedupe(fs []Finding) []Finding {
	seen := map[string]bool{}
	var out []Finding
	for _, f := range fs {
		k := f.ID + "\x00" + f.Message + "\x00" + strings.Join(f.Policies, ",")
		if !seen[k] {
			seen[k] = true
			out = append(out, f)
		}
	}
	return out
}

// restrictingKeys are condition keys that limit who or where a request comes from. A public
// principal with one of these is not public.
var restrictingKeys = map[string]bool{
	"aws:sourcearn": true, "aws:sourceaccount": true, "aws:principalorgid": true, "aws:principalorgpaths": true,
	"aws:sourcevpc": true, "aws:sourcevpce": true, "aws:sourceip": true, "aws:principalaccount": true,
	"aws:principalarn": true, "aws:sourceowner": true, "aws:sourceorgid": true, "aws:sourceorgpaths": true,
	"aws:userid": true, "aws:principalservicename": true, "kms:calleraccount": true, "kms:viaservice": true,
	"aws:resourceaccount": true, "aws:resourceorgid": true,
}

func restricted(st policy.Statement) bool {
	for _, k := range st.ConditionKeys() {
		if restrictingKeys[k] {
			return true
		}
	}
	return false
}

func public(st policy.Statement) bool {
	for typ, ids := range st.Principal {
		if typ != "*" && typ != "AWS" {
			continue
		}
		for _, id := range ids {
			if id == "*" {
				return true
			}
		}
	}
	return st.NotPrincipal != nil
}

func resource(who string, r policy.Named) []Finding {
	var out []Finding
	for _, st := range r.Doc.Statements {
		if st.Effect != "Allow" || !public(st) || restricted(st) {
			continue
		}
		actions := st.Action
		if actions == nil {
			actions = []string{"everything except " + strings.Join(st.NotAction, ", ")}
		}
		why := "Principal \"*\""
		if st.NotPrincipal != nil {
			why = "NotPrincipal (everyone except the principals listed)"
		}
		out = append(out, Finding{ID: "IAM010", Severity: "high", Subject: who, Policies: []string{label(r, st)},
			Message: fmt.Sprintf("allows %s to anyone: %s with no condition on the caller's account, organisation, network or source", strings.Join(actions, ", "), why)})
	}
	return out
}

// oidcSubjects are the condition keys an OIDC trust must check, by provider host.
var oidcSubjects = map[string]string{
	"token.actions.githubusercontent.com": "GitHub Actions",
	"gitlab.com":                          "GitLab CI",
	"app.terraform.io":                    "Terraform Cloud",
	"oidc.circleci.com":                   "CircleCI",
	"api.bitbucket.org":                   "Bitbucket Pipelines",
}

func trust(who string, s policy.Subject) []Finding {
	var out []Finding
	own := accountOf(s.Arn)
	for _, st := range s.Trust.Statements {
		if st.Effect != "Allow" {
			continue
		}
		at := []string{label(policy.Named{Name: "trust policy", Doc: s.Trust}, st)}
		if public(st) && !restricted(st) {
			out = append(out, Finding{ID: "IAM020", Severity: "critical", Subject: who, Policies: at,
				Message: "can be assumed by any AWS principal in any account: the trust policy's Principal is \"*\" with no restricting condition"})
		}
		for _, fed := range st.Principal["Federated"] {
			host := fed
			if i := strings.Index(fed, "oidc-provider/"); i >= 0 {
				host = fed[i+len("oidc-provider/"):]
			}
			name, known := oidcSubjects[host]
			if !known && !strings.Contains(host, "oidc.eks.") {
				continue
			}
			if !known {
				name = "EKS service accounts"
			}
			subs := st.ConditionValues(host + ":sub")
			switch {
			case len(subs) == 0 && !known:
				out = append(out, Finding{ID: "IAM021", Severity: "high", Subject: who, Policies: at,
					Message: fmt.Sprintf("trusts %s with no condition on %s:sub: every service account in that cluster can assume it", name, host)})
			case len(subs) == 0:
				out = append(out, Finding{ID: "IAM021", Severity: "critical", Subject: who, Policies: at,
					Message: fmt.Sprintf("trusts %s tokens with no condition on %s:sub: a token issued to anyone's %s job, not only yours, can assume it", name, host, name)})
			default:
				for _, sub := range subs {
					if wideSubject(sub) {
						out = append(out, Finding{ID: "IAM021", Severity: "high", Subject: who, Policies: at,
							Message: fmt.Sprintf("trusts %s tokens whose subject matches %q: that covers far more than one repository, branch or service account", name, sub)})
					}
				}
			}
		}
		for _, p := range st.Principal["AWS"] {
			acct := accountOf(p)
			if acct == "" || own == "" || acct == own || !strings.HasSuffix(p, ":root") {
				continue
			}
			if len(st.ConditionValues("sts:ExternalId")) == 0 && !restricted(st) {
				out = append(out, Finding{ID: "IAM022", Severity: "medium", Subject: who, Policies: at,
					Message: fmt.Sprintf("trusts all of account %s with no sts:ExternalId condition: any principal there with sts:AssumeRole can assume it, and a third party acting for several customers can be tricked into doing so (the confused deputy)", acct)})
			}
		}
	}
	return out
}

// wideSubject reports an OIDC subject pattern that matches whole organisations or any branch.
func wideSubject(sub string) bool {
	if sub == "*" {
		return true
	}
	parts := strings.Split(sub, ":")
	// GitHub: repo:ORG/REPO:ref:refs/heads/main. A * in the repository part, or a pattern that
	// stops at the repository with a trailing *, matches every ref of every repository.
	if len(parts) >= 2 && parts[0] == "repo" {
		repo := parts[1]
		return strings.Contains(repo, "*") || len(parts) == 2 || (len(parts) >= 3 && parts[2] == "*")
	}
	return strings.HasSuffix(sub, ":*") || strings.HasPrefix(sub, "*")
}

func accountOf(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) >= 5 && strings.HasPrefix(arn, "arn:") {
		return parts[4]
	}
	if len(arn) == 12 && strings.Trim(arn, "0123456789") == "" {
		return arn
	}
	return ""
}

// statementShape reports documents AWS would refuse or read differently than intended.
func statementShape(who string, docs []policy.Named) []Finding {
	var out []Finding
	for _, n := range docs {
		if n.Doc.Version != "2012-10-17" {
			v := n.Doc.Version
			if v == "" {
				v = "missing"
			}
			out = append(out, Finding{ID: "IAM030", Severity: "low", Subject: who, Policies: []string{n.Name},
				Message: fmt.Sprintf("Version is %s, not 2012-10-17: policy variables such as ${aws:username} are then taken literally", v)})
		}
		for _, st := range n.Doc.Statements {
			bad := ""
			switch {
			case st.Effect != "Allow" && st.Effect != "Deny":
				bad = fmt.Sprintf("Effect %q is neither Allow nor Deny", st.Effect)
			case (st.Action == nil) == (st.NotAction == nil):
				bad = "a statement needs exactly one of Action and NotAction"
			case st.Principal == nil && st.NotPrincipal == nil && (st.Resource == nil) == (st.NotResource == nil):
				bad = "an identity policy statement needs exactly one of Resource and NotResource"
			}
			if bad != "" {
				out = append(out, Finding{ID: "IAM031", Severity: "high", Subject: who, Policies: []string{label(n, st)},
					Message: bad + "; AWS rejects the policy"})
			}
		}
	}
	return out
}

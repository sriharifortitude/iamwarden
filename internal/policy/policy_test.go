package policy

import (
	"net/url"
	"reflect"
	"strings"
	"testing"
)

func mustParse(t *testing.T, s string) *Document {
	t.Helper()
	d, err := Parse([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestStringsAndListsAreTheSame(t *testing.T) {
	a := mustParse(t, `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}}`)
	b := mustParse(t, `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":["*"]}]}`)
	if !reflect.DeepEqual(a.Statements[0].Action, b.Statements[0].Action) || !reflect.DeepEqual(a.Statements[0].Resource, b.Statements[0].Resource) {
		t.Fatalf("%+v %+v", a, b)
	}
}

func TestPrincipalsAndConditions(t *testing.T) {
	d := mustParse(t, `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"*",
		"Condition":{"StringEquals":{"AWS:SourceAccount":"111122223333"},"Bool":{"aws:SecureTransport":true},"NumericLessThan":{"s3:max-keys":[10,20]}}},
		{"Effect":"Allow","Principal":{"AWS":["arn:aws:iam::111122223333:root"],"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}`)
	s0 := d.Statements[0]
	if !reflect.DeepEqual(s0.Principal, map[string][]string{"*": {"*"}}) {
		t.Fatalf("%+v", s0.Principal)
	}
	if got := s0.ConditionValues("aws:sourceaccount"); !reflect.DeepEqual(got, []string{"111122223333"}) {
		t.Fatalf("condition keys are case-insensitive: %v", got)
	}
	if got := s0.ConditionValues("aws:SecureTransport"); !reflect.DeepEqual(got, []string{"true"}) {
		t.Fatalf("an unquoted boolean: %v", got)
	}
	if got := s0.ConditionValues("s3:max-keys"); !reflect.DeepEqual(got, []string{"10", "20"}) {
		t.Fatalf("a list of numbers: %v", got)
	}
	if !reflect.DeepEqual(s0.ConditionKeys(), []string{"aws:securetransport", "aws:sourceaccount", "s3:max-keys"}) {
		t.Fatalf("%v", s0.ConditionKeys())
	}
	if d.Statements[1].Principal["Service"][0] != "ec2.amazonaws.com" || d.Statements[1].Index != 1 {
		t.Fatalf("%+v", d.Statements[1])
	}
}

func TestURLEncodedDocument(t *testing.T) {
	doc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}`
	quoted := `"` + url.QueryEscape(doc) + `"`
	if d := mustParse(t, quoted); d.Statements[0].Action[0] != "s3:*" {
		t.Fatalf("%+v", d)
	}
}

func TestParseErrors(t *testing.T) {
	for _, s := range []string{`{}`, `{"Statement":[]}`, `not json`, `{"Statement":[{"Action":5}]}`, `{"Statement":[{"Principal":5}]}`,
		`{"Statement":[{"Condition":{"StringEquals":"x"}}]}`, `"%%%"`} {
		if _, err := Parse([]byte(s)); err == nil {
			t.Errorf("%s: want an error", s)
		}
	}
}

func TestActionMatching(t *testing.T) {
	for _, c := range []struct {
		pattern, action string
		want            bool
	}{
		{"*", "iam:PassRole", true},
		{"iam:*", "IAM:passrole", true},
		{"iam:Pass*", "iam:PassRole", true},
		{"iam:Get*", "iam:PassRole", false},
		{"iam:?assRole", "iam:PassRole", true},
		{"s3:*Object", "s3:GetObject", true},
		{"s3:*Object", "s3:GetObjectAcl", false},
		{"ec2:*", "ec2messages:Send", false},
		{"*:*", "s3:GetObject", true},
		{"", "s3:GetObject", false},
		{"s3:Get*", "s3:Get", true},
		{"s3:Get**", "s3:Get", true},
		{"s3:Get*?", "s3:Get", false},
	} {
		if got := MatchAction(c.pattern, c.action); got != c.want {
			t.Errorf("%q vs %q: %v", c.pattern, c.action, got)
		}
	}
	if MatchResource("arn:aws:s3:::Bucket/*", "arn:aws:s3:::bucket/x") {
		t.Error("ARNs are case-sensitive")
	}
}

func TestWildcardIsLinear(t *testing.T) {
	p := strings.Repeat("a*", 2000) + "b"
	s := strings.Repeat("a", 4000)
	if MatchAction(p, s) {
		t.Fatal("should not match")
	}
}

func TestAllowsWithNotAction(t *testing.T) {
	st := mustParse(t, `{"Statement":{"Effect":"Allow","NotAction":["iam:*","organizations:*"],"NotResource":"arn:aws:s3:::secret/*"}}`).Statements[0]
	if st.Allows("iam:PassRole") || !st.Allows("ec2:RunInstances") || !st.AnyResource() {
		t.Fatalf("%+v", st)
	}
	if st.CoversResource("arn:aws:s3:::secret/a") || !st.CoversResource("arn:aws:s3:::other/a") {
		t.Fatal("NotResource")
	}
	plain := mustParse(t, `{"Statement":{"Effect":"Allow","Action":"s3:Get*","Resource":["arn:aws:s3:::a/*"]}}`).Statements[0]
	if plain.AnyResource() || !plain.CoversResource("arn:aws:s3:::a/x") || plain.Allows("s3:PutObject") {
		t.Fatalf("%+v", plain)
	}
}

// --- input formats ----------------------------------------------------------------------------

const sampleExport = `{
 "UserDetailList": [
  {"UserName": "alice", "Arn": "arn:aws:iam::111122223333:user/alice", "GroupList": ["devs"],
   "UserPolicyList": [{"PolicyName": "own", "PolicyDocument": {"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:ListBucket","Resource":"*"}}}],
   "AttachedManagedPolicies": [{"PolicyName": "Gone", "PolicyArn": "arn:aws:iam::aws:policy/Gone"}]}
 ],
 "GroupDetailList": [
  {"GroupName": "devs", "Arn": "arn:aws:iam::111122223333:group/devs", "GroupPolicyList": [],
   "AttachedManagedPolicies": [{"PolicyName": "Deploy", "PolicyArn": "arn:aws:iam::111122223333:policy/Deploy"}]}
 ],
 "RoleDetailList": [
  {"RoleName": "ci", "Arn": "arn:aws:iam::111122223333:role/ci",
   "AssumeRolePolicyDocument": "%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Principal%22%3A%7B%22Service%22%3A%22ec2.amazonaws.com%22%7D%2C%22Action%22%3A%22sts%3AAssumeRole%22%7D%5D%7D",
   "RolePolicyList": [], "AttachedManagedPolicies": [{"PolicyName": "Deploy", "PolicyArn": "arn:aws:iam::111122223333:policy/Deploy"}]}
 ],
 "Policies": [
  {"PolicyName": "Deploy", "Arn": "arn:aws:iam::111122223333:policy/Deploy", "DefaultVersionId": "v2",
   "PolicyVersionList": [
    {"VersionId": "v1", "IsDefaultVersion": false, "Document": {"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}},
    {"VersionId": "v2", "IsDefaultVersion": true, "Document": {"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"lambda:UpdateFunctionCode","Resource":"*"}}}
   ]}
 ]
}`

func TestAccountAuthorizationDetails(t *testing.T) {
	in, err := Read("a.json", []byte(sampleExport))
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]Subject{}
	for _, s := range in.Subjects {
		byName[s.Kind+" "+s.Name] = s
	}
	alice := byName["user alice"]
	var names []string
	for _, n := range alice.Identity {
		names = append(names, n.Name)
	}
	if strings.Join(names, ",") != "inline own,Deploy (through group devs)" {
		t.Fatalf("alice's policies: %v", names)
	}
	if alice.Identity[1].Doc.Statements[0].Action[0] != "lambda:UpdateFunctionCode" {
		t.Fatal("only the default version of a managed policy counts")
	}
	ci := byName["role ci"]
	if ci.Trust == nil || ci.Trust.Statements[0].Principal["Service"][0] != "ec2.amazonaws.com" {
		t.Fatalf("the URL-encoded trust policy: %+v", ci.Trust)
	}
	if len(in.Problems) != 1 || !strings.Contains(in.Problems[0], "Gone") {
		t.Fatalf("a missing attached policy must be reported: %v", in.Problems)
	}
}

func TestWrappersAndKinds(t *testing.T) {
	cases := map[string]string{
		`{"PolicyVersion":{"Document":{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:*","Resource":"*"}}}}`:                                         "policy",
		`{"Role":{"RoleName":"r","Arn":"arn:aws:iam::1:role/r","AssumeRolePolicyDocument":{"Statement":{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole"}}}}`: "role",
		`{"Policy":"{\"Statement\":{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"s3:GetObject\",\"Resource\":\"*\"}}"}`:                                        "resource policy",
		`{"Statement":{"Effect":"Allow","Principal":{"Federated":"x"},"Action":"sts:AssumeRoleWithWebIdentity"}}`:                                                       "role",
	}
	for text, kind := range cases {
		in, err := Read("x.json", []byte(text))
		if err != nil || len(in.Subjects) != 1 || in.Subjects[0].Kind != kind {
			t.Errorf("%s: %v %+v", text, err, in)
		}
	}
	if _, err := Read("x.json", []byte(`{"Something":"else"}`)); err == nil {
		t.Error("an unknown shape must be refused")
	}
	if _, err := Read("x.json", []byte(`[1,2]`)); err == nil {
		t.Error("not an object")
	}
}

func FuzzParse(f *testing.F) {
	f.Add(`{"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`)
	f.Add(sampleExport)
	f.Add(`"%7B%22Statement%22%3A%5B%5D%7D"`)
	f.Fuzz(func(t *testing.T, s string) {
		if d, err := Parse([]byte(s)); err == nil {
			for _, st := range d.Statements {
				st.Allows("iam:PassRole")
				st.AnyResource()
				st.ConditionKeys()
			}
		}
		_, _ = Read("f", []byte(s))
	})
}

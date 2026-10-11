package rules

import (
	"strings"
	"testing"

	"github.com/sriharifortitude/iamwarden/internal/policy"
)

func run(t *testing.T, doc string) []Finding {
	t.Helper()
	in, err := policy.Read("p.json", []byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	return Check(in)
}

// identity wraps statements in an identity policy document.
func idDoc(statements string) string {
	return `{"Version":"2012-10-17","Statement":[` + statements + `]}`
}

func allow(actions, resource string) string {
	return `{"Effect":"Allow","Action":` + actions + `,"Resource":` + resource + `}`
}

func has(fs []Finding, id, sev, fragment string) bool {
	for _, f := range fs {
		if f.ID == id && f.Severity == sev && strings.Contains(f.Message, fragment) {
			return true
		}
	}
	return false
}

func list(fs []Finding) string {
	var out []string
	for _, f := range fs {
		out = append(out, f.ID+"/"+f.Severity+": "+f.Message)
	}
	return strings.Join(out, "\n")
}

func TestAdministrator(t *testing.T) {
	fs := run(t, idDoc(allow(`"*"`, `"*"`)))
	if len(fs) != 1 || !has(fs, "IAM001", "critical", "administrator") {
		t.Fatal(list(fs))
	}
	// Under a condition it is one level less.
	fs = run(t, idDoc(`{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"Bool":{"aws:MultiFactorAuthPresent":"true"}}}`))
	if !has(fs, "IAM001", "high", "conditions hold") {
		t.Fatal(list(fs))
	}
}

func TestManyServicesAreNotEverything(t *testing.T) {
	fs := run(t, idDoc(allow(`["iam:*","s3:*"]`, `"*"`)))
	if has(fs, "IAM001", "critical", "") || !has(fs, "IAM002", "high", "iam:CreatePolicyVersion") {
		t.Fatal("iam:* and s3:* is dangerous, not every action:\n" + list(fs))
	}
}

func TestEachEscalationMethod(t *testing.T) {
	for _, e := range escalations {
		var quoted []string
		for _, a := range e.actions {
			quoted = append(quoted, `"`+a+`"`)
		}
		fs := run(t, idDoc(allow("["+strings.Join(quoted, ",")+"]", `"*"`)))
		if !has(fs, "IAM002", "high", e.how) {
			t.Errorf("%v: want a high IAM002, got\n%s", e.actions, list(fs))
		}
		if len(e.actions) > 1 {
			// Every action is needed: drop the last and the method must not be reported.
			fs = run(t, idDoc(allow("["+strings.Join(quoted[:len(quoted)-1], ",")+"]", `"*"`)))
			if has(fs, "IAM002", "high", e.how) {
				t.Errorf("%v without %s should not be reported:\n%s", e.actions, e.actions[len(e.actions)-1], list(fs))
			}
		}
	}
}

func TestWildcardsAndNotActionReachEscalations(t *testing.T) {
	if fs := run(t, idDoc(allow(`"iam:Put*"`, `"*"`))); !has(fs, "IAM002", "high", "iam:PutUserPolicy") {
		t.Fatal(list(fs))
	}
	fs := run(t, idDoc(`{"Effect":"Allow","NotAction":["iam:*","organizations:*"],"Resource":"*"}`))
	if !has(fs, "IAM002", "high", "lambda:UpdateFunctionCode") || has(fs, "IAM002", "high", "iam:") || !has(fs, "IAM003", "medium", "NotAction") {
		t.Fatal(list(fs))
	}
}

func TestLimitedResourcesAndConditionsLowerTheSeverity(t *testing.T) {
	if fs := run(t, idDoc(allow(`"lambda:UpdateFunctionCode"`, `"arn:aws:lambda:eu-west-1:111122223333:function:app"`))); !has(fs, "IAM002", "medium", "on the resources the policy names") {
		t.Fatal(list(fs))
	}
	fs := run(t, idDoc(`{"Effect":"Allow","Action":"lambda:UpdateFunctionCode","Resource":"arn:aws:lambda:*:*:function:app","Condition":{"StringEquals":{"aws:RequestedRegion":"eu-west-1"}}}`))
	if !has(fs, "IAM002", "low", "conditions hold") {
		t.Fatal(list(fs))
	}
}

func TestPassedToServiceDecidesWhichPassRoleMethodsApply(t *testing.T) {
	doc := idDoc(`{"Effect":"Allow","Action":"iam:PassRole","Resource":"*","Condition":{"StringEquals":{"iam:PassedToService":"lambda.amazonaws.com"}}},` +
		allow(`["ec2:RunInstances","lambda:CreateFunction","lambda:InvokeFunction"]`, `"*"`))
	fs := run(t, doc)
	if has(fs, "IAM002", "high", "ec2:RunInstances") {
		t.Fatal("a role that may only be passed to Lambda cannot be put on an instance:\n" + list(fs))
	}
	if !has(fs, "IAM002", "high", "lambda:CreateFunction") {
		t.Fatal("PassedToService naming Lambda limits nothing for the Lambda method:\n" + list(fs))
	}
	fs = run(t, idDoc(`{"Effect":"Allow","Action":"iam:PassRole","Resource":"*","Condition":{"StringLike":{"iam:PassedToService":"*.amazonaws.com"}}},`+allow(`"ec2:RunInstances"`, `"*"`)))
	if !has(fs, "IAM002", "high", "ec2:RunInstances") {
		t.Fatal(list(fs))
	}
}

func TestAnUnconditionalDenyRemovesAGrant(t *testing.T) {
	doc := idDoc(allow(`"iam:*"`, `"*"`) + `,{"Effect":"Deny","Action":"iam:CreatePolicyVersion","Resource":"*"}`)
	fs := run(t, doc)
	if has(fs, "IAM002", "high", "iam:CreatePolicyVersion") || !has(fs, "IAM002", "high", "iam:AttachUserPolicy") {
		t.Fatal(list(fs))
	}
	// A conditional Deny may not apply, so the grant still counts.
	doc = idDoc(allow(`"iam:CreatePolicyVersion"`, `"*"`) + `,{"Effect":"Deny","Action":"iam:*","Resource":"*","Condition":{"Bool":{"aws:MultiFactorAuthPresent":"false"}}}`)
	if fs := run(t, doc); !has(fs, "IAM002", "high", "iam:CreatePolicyVersion") {
		t.Fatal(list(fs))
	}
}

func TestBroadServiceGrantsAndSecrets(t *testing.T) {
	fs := run(t, idDoc(allow(`["s3:*","secretsmanager:GetSecretValue"]`, `"*"`)))
	if !has(fs, "IAM005", "medium", "every s3 resource") || !has(fs, "IAM004", "medium", "secretsmanager:GetSecretValue") {
		t.Fatal(list(fs))
	}
	if fs := run(t, idDoc(allow(`["s3:*","secretsmanager:GetSecretValue"]`, `"arn:aws:s3:::app/*"`))); len(fs) != 0 {
		t.Fatal(list(fs))
	}
	if fs := run(t, idDoc(`{"Effect":"Allow","Action":"s3:GetObject","NotResource":"arn:aws:s3:::secret/*"}`)); !has(fs, "IAM003", "medium", "NotResource") {
		t.Fatal(list(fs))
	}
}

func TestAReadOnlyPolicyIsClean(t *testing.T) {
	if fs := run(t, idDoc(allow(`["s3:GetObject","s3:ListBucket","ec2:Describe*","iam:Get*","iam:List*"]`, `"*"`))); len(fs) != 0 {
		t.Fatal(list(fs))
	}
}

func resourcePolicy(statement string) string {
	return `{"Version":"2012-10-17","Statement":[` + statement + `]}`
}

func TestPublicResourcePolicies(t *testing.T) {
	for _, p := range []string{`"*"`, `{"AWS":"*"}`, `{"AWS":["arn:aws:iam::111122223333:root","*"]}`} {
		fs := run(t, resourcePolicy(`{"Effect":"Allow","Principal":`+p+`,"Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}`))
		if !has(fs, "IAM010", "high", "anyone") {
			t.Errorf("%s: %s", p, list(fs))
		}
	}
	fs := run(t, resourcePolicy(`{"Effect":"Allow","NotPrincipal":{"AWS":"arn:aws:iam::111122223333:root"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}`))
	if !has(fs, "IAM010", "high", "NotPrincipal") {
		t.Fatal(list(fs))
	}
	for _, key := range []string{"aws:SourceArn", "aws:PrincipalOrgID", "aws:SourceVpce", "aws:SourceAccount"} {
		fs := run(t, resourcePolicy(`{"Effect":"Allow","Principal":"*","Action":"sqs:SendMessage","Resource":"*","Condition":{"StringEquals":{"`+key+`":"x"}}}`))
		if has(fs, "IAM010", "high", "") {
			t.Errorf("%s restricts the caller: %s", key, list(fs))
		}
	}
	// A condition that does not restrict who is calling does not make it private.
	fs = run(t, resourcePolicy(`{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"*","Condition":{"Bool":{"aws:SecureTransport":"true"}}}`))
	if !has(fs, "IAM010", "high", "") {
		t.Fatal(list(fs))
	}
}

func role(arn, trust string) string {
	return `{"Role":{"RoleName":"r","Arn":"` + arn + `","AssumeRolePolicyDocument":{"Version":"2012-10-17","Statement":[` + trust + `]}}}`
}

const gha = "arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com"

func TestTrustPolicies(t *testing.T) {
	cases := []struct {
		trust, id, sev, fragment string
	}{
		{`{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole"}`, "IAM020", "critical", "any AWS principal"},
		{`{"Effect":"Allow","Principal":{"Federated":"` + gha + `"},"Action":"sts:AssumeRoleWithWebIdentity",
			"Condition":{"StringEquals":{"token.actions.githubusercontent.com:aud":"sts.amazonaws.com"}}}`, "IAM021", "critical", "no condition on token.actions.githubusercontent.com:sub"},
		{`{"Effect":"Allow","Principal":{"Federated":"` + gha + `"},"Action":"sts:AssumeRoleWithWebIdentity",
			"Condition":{"StringLike":{"token.actions.githubusercontent.com:sub":"repo:acme/*"}}}`, "IAM021", "high", "repo:acme/*"},
		{`{"Effect":"Allow","Principal":{"Federated":"` + gha + `"},"Action":"sts:AssumeRoleWithWebIdentity",
			"Condition":{"StringLike":{"token.actions.githubusercontent.com:sub":"repo:acme/app:*"}}}`, "IAM021", "high", "repo:acme/app:*"},
		{`{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::111122223333:oidc-provider/oidc.eks.eu-west-1.amazonaws.com/id/ABC"},"Action":"sts:AssumeRoleWithWebIdentity"}`, "IAM021", "high", "every service account in that cluster"},
		{`{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::999988887777:root"},"Action":"sts:AssumeRole"}`, "IAM022", "medium", "account 999988887777"},
	}
	for _, c := range cases {
		fs := run(t, role("arn:aws:iam::111122223333:role/r", c.trust))
		if !has(fs, c.id, c.sev, c.fragment) {
			t.Errorf("%s: want %s/%s with %q, got\n%s", c.trust, c.id, c.sev, c.fragment, list(fs))
		}
	}
}

func TestSafeTrustPolicies(t *testing.T) {
	for _, trust := range []string{
		`{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}`,
		`{"Effect":"Allow","Principal":{"Federated":"` + gha + `"},"Action":"sts:AssumeRoleWithWebIdentity",
			"Condition":{"StringEquals":{"token.actions.githubusercontent.com:sub":"repo:acme/app:ref:refs/heads/main"}}}`,
		`{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::999988887777:root"},"Action":"sts:AssumeRole","Condition":{"StringEquals":{"sts:ExternalId":"x7"}}}`,
		`{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111122223333:root"},"Action":"sts:AssumeRole"}`,
		`{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole","Condition":{"StringEquals":{"aws:PrincipalOrgID":"o-abc"}}}`,
	} {
		if fs := run(t, role("arn:aws:iam::111122223333:role/r", trust)); len(fs) != 0 {
			t.Errorf("%s:\n%s", trust, list(fs))
		}
	}
}

func TestWideSubjects(t *testing.T) {
	for sub, want := range map[string]bool{
		"*": true, "repo:acme/*": true, "repo:acme/app:*": true, "repo:*/app:ref:refs/heads/main": true, "repo:acme/app": true,
		"repo:acme/app:ref:refs/heads/main": false, "repo:acme/app:environment:prod": false, "system:serviceaccount:ns:sa": false,
		"system:serviceaccount:ns:*": true,
	} {
		if got := wideSubject(sub); got != want {
			t.Errorf("%s: %v", sub, got)
		}
	}
}

func TestDocumentShape(t *testing.T) {
	fs := run(t, `{"Version":"2008-10-17","Statement":[{"Effect":"Permit","Action":"s3:GetObject","Resource":"*"},{"Effect":"Allow","Resource":"*"},{"Effect":"Allow","Action":"s3:GetObject"},{"Effect":"Allow","Action":"s3:GetObject","NotAction":"s3:PutObject","Resource":"*"}]}`)
	n := 0
	for _, f := range fs {
		if f.ID == "IAM031" {
			n++
		}
	}
	if !has(fs, "IAM030", "low", "2008-10-17") || n != 4 {
		t.Fatal(list(fs))
	}
}

func TestFindingsNameTheirPolicies(t *testing.T) {
	fs := run(t, idDoc(`{"Sid":"Deploy","Effect":"Allow","Action":"lambda:UpdateFunctionCode","Resource":"*"}`))
	if len(fs) != 1 || strings.Join(fs[0].Policies, ",") != "p.json (Deploy)" || fs[0].Subject != "policy p.json" {
		t.Fatalf("%+v", fs)
	}
}

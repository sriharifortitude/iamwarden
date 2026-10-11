# iamwarden

[![CI](https://github.com/sriharifortitude/iamwarden/actions/workflows/ci.yml/badge.svg)](https://github.com/sriharifortitude/iamwarden/actions/workflows/ci.yml)

Finds AWS IAM permissions that reach further than they look: privilege-escalation paths
across all of a principal's policies, resource policies open to anyone, and role trust
policies that let the wrong workload in. Works offline on policy files or on a whole
account's `get-account-authorization-details` export. Go, standard library only, MIT.

## What it is for

Most IAM mistakes are not `"Action": "*"`. They are a developers group that may update any
Lambda function (and so run code as any function's role), a CI role that may pass any role to an
EC2 instance, a GitHub Actions trust policy that checks the audience but not which repository
is asking, and a bucket policy whose `Principal: "*"` is "protected" by a condition that does
not restrict the caller at all:

<!-- demo:start -->
```
$ iamwarden testdata/account.json testdata/bucket-policy.json
group developers
  IAM002 high     can escalate its privileges: with lambda:UpdateFunctionCode it can replace the code of a function that has a privileged role
           from inline deploy-functions (Functions)

role github-deploy
  IAM021 critical trusts GitHub Actions tokens with no condition on token.actions.githubusercontent.com:sub: a token issued to anyone's GitHub Actions job, not only yours, can assume it
           from trust policy
  IAM002 high     can escalate its privileges: with iam:PassRole + ec2:RunInstances it can start an instance with a privileged role and read its credentials
           from ci-runner (PassAnyRole); ci-runner (Launch)
  IAM005 medium   allows s3:* on every resource: full control of every s3 resource in the account
           from ci-runner (Artifacts)

user dana
  IAM002 high     can escalate its privileges: with lambda:UpdateFunctionCode it can replace the code of a function that has a privileged role
           from inline deploy-functions (through group developers) (Functions)

resource policy testdata/bucket-policy.json
  IAM010 high     allows s3:GetObject to anyone: Principal "*" with no condition on the caller's account, organisation, network or source
           from testdata/bucket-policy.json (PublicRead)

2 file(s) read; 1 critical, 4 high, 1 medium
```
<!-- demo:end -->

dana holds no policy of her own: the escalation comes from her group, and the finding says so.
The auditor (SecurityAudit) and the batch worker (read access to one bucket) are not reported.
The bucket policy's second statement, which admits CloudFront for one distribution through
`aws:SourceArn`, is correctly left alone.

## Usage

```bash
go install github.com/sriharifortitude/iamwarden/cmd/iamwarden@v0.1.0

aws iam get-account-authorization-details > account.json
iamwarden account.json                        # every user, group and role, judged with all their policies
iamwarden policies/                           # a directory of policy documents (*.json)
aws s3api get-bucket-policy --bucket b | iamwarden -
iamwarden infra/policies --fail-on medium     # in CI, on policies before they are applied
```

It reads a policy document of any kind (identity, resource, trust), the authorization-details
export, and the AWS CLI's wrappers around a single policy (`get-policy-version`, `get-role`,
`get-bucket-policy`). URL-encoded documents are decoded. Exit codes: 0 nothing at or above
`--fail-on` (default high), 1 at least one finding is, 2 a usage error or unreadable input.

## Checks

| ID | Severity | What it finds |
|---|---|---|
| IAM001 | critical | every action on every resource: an administrator |
| IAM002 | high | a privilege-escalation path: one of 25 combinations of actions, from `iam:CreatePolicyVersion` to `iam:PassRole` + `ec2:RunInstances` and `ssm:SendCommand`, held across all of the principal's policies |
| IAM003 | medium | Allow with NotAction or NotResource: everything else, including what AWS launches later |
| IAM004 | medium | secret-reading actions (Secrets Manager, SSM parameters, KMS Decrypt) on every resource |
| IAM005 | medium | `service:*` on every resource |
| IAM010 | high | a resource policy open to anyone (`Principal: "*"` or NotPrincipal) with no condition restricting the caller |
| IAM020 | critical | a role any AWS principal anywhere can assume |
| IAM021 | critical / high | an OIDC trust (GitHub Actions, GitLab, Terraform Cloud, CircleCI, Bitbucket, EKS) with no `sub` condition, or one that covers whole organisations, every branch or a whole namespace |
| IAM022 | medium | a role trusted by an entire external account with no `sts:ExternalId` |
| IAM030 / IAM031 | low / high | a policy Version other than 2012-10-17; a statement AWS would reject |
| IAM090 | info | a document that could not be read, or an attached policy missing from the export |

Severity drops one level when a grant is limited to named resources, and one more when it
holds only under conditions. An unconditional Deny on every resource removes a grant. A
conditional one does not, because whether it applies is not known. For methods that pass a
role, `iam:PassedToService` is honoured: a role that may only be passed to Lambda cannot be
put on an instance. [ADR 1](docs/adr/0001-judge-the-subject-not-the-statement.md) and
[ADR 2](docs/adr/0002-who-can-get-in.md) have the reasoning.

## Tested

```bash
go test ./...                       # 29 tests and a fuzz target
./scripts/corpus.sh                 # every AWS managed policy, with known verdicts checked
```

**Against every AWS managed policy.** The z0ph/MAMIP project archives AWS's 1,664 managed
policies; CI fetches it at a fixed commit (it is GPL-3.0, so it is not copied here) and runs
iamwarden over all of them in about two seconds. Two files in that archive are empty and are
reported as unreadable. The script fails unless verdicts that are known independently hold:

- AdministratorAccess is an administrator.
- IAMFullAccess and PowerUserAccess can escalate. PowerUserAccess excludes IAM but allows
  `lambda:UpdateFunctionCode` and `ssm:SendCommand`, which is a well-known gap.
- SecurityAudit, ViewOnlyAccess and AmazonS3ReadOnlyAccess have no findings.
- ReadOnlyAccess cannot escalate. It is reported once, because it can read SSM parameters.

45 managed policies carry a high or critical escalation path, and 554 grant `service:*` on
every resource.

The corpus also changed the tool twice. AWSMcpServiceActionsFullAccess is `*` on `*` under a
condition, and was reported as a full administrator until conditional grants were made one
level less severe. Many PassRole grants carry `iam:PassedToService`, and before that condition
was honoured, 29 of 53 PassRole + CloudFormation findings were impossible ones.

**Mutation testing.** I broke the code in 45 places on purpose. On the first run, 3 mutants survived and 4 did not compile; I rewrote those so they do. The survivors were gaps in the tests: a wildcard pattern that ends in * after the action has run out (s3:Get* against s3:Get) was never tested; nothing showed that iam:* plus s3:* is not an administrator; and a statement with both Action and NotAction, which AWS rejects, had no test. All 45 are caught now.

**Not tested:** against AWS's own policy evaluation. There is no offline reference
implementation, and IAM Access Analyzer needs an account. The escalation list is a list:
newer methods that need actions not on it are not found.

## Limits

- **Policies, not effective permissions.** Permission boundaries, service control policies,
  session policies and resource policies on the target can each take away what is reported
  here. A finding means "these policies grant it".
- **Resources are judged coarsely**: "every resource" against "the resources named". Whether
  a named role is itself an administrator is not worked out.
- **No group membership beyond the export**, and no account ID unless the export or a role's
  ARN gives one, so cross-account trust is judged only where the role's ARN is known.
- **Prior art.** [Cloudsplaining](https://github.com/salesforce/cloudsplaining) (Salesforce)
  covers similar ground for identity policies, with an HTML report. iamwarden adds trust and
  resource policies, OIDC subject checks and `PassedToService`, is one static binary, and is
  meant to run in CI on policy files before they are applied.

## Licence

MIT.

# 2. Who can get in: resource and trust policies

Status: accepted

## Context

Identity policies say what a principal may do. Resource policies and role trust policies say
who may come in, and their worst mistakes are reachable from outside the account:

- A bucket, queue or key policy with `Principal: "*"`. It is often meant to admit one service,
  through a condition, but the condition chosen (`aws:SecureTransport`, say) does not restrict
  the caller at all.
- A role trusted by GitHub Actions' OIDC provider with no condition on `sub`. Every workflow in
  every repository on GitHub can assume it. This is a documented, recurring incident pattern.
- A role trusted by a whole external account with no `sts:ExternalId`: the confused-deputy
  problem AWS describes for third-party access.

## Decision

A public principal is reported unless the statement has a condition on a key that restricts
the caller: source ARN, account, organisation, VPC or endpoint, IP address, principal ARN or
account, and a few service-specific equivalents. Any other condition does not count.

An OIDC trust is reported when it has no condition on `<provider>:sub`. It is also reported
when the subject pattern covers far more than one workload: `*`, a wildcard in the repository
name, `repo:org/*`, a repository with every ref, or a whole Kubernetes namespace. Known
providers are GitHub, GitLab, Terraform Cloud, CircleCI and Bitbucket. EKS clusters are
recognised by their issuer host.

Cross-account trust needs the role's own account, so it is judged only when the role's ARN is
known (from get-role or the authorization details export).

## Consequences

- The list of restricting keys is a judgement. A condition this tool does not recognise makes a
  public statement look public, and a reviewer has to say otherwise; the opposite mistake,
  missing a public bucket, is the one to avoid.
- Without the account's own ID, an `arn:aws:iam::...:root` principal cannot be told apart from
  the account itself, and is not reported.

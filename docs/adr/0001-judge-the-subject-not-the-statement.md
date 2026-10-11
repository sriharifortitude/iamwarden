# 1. Judge the subject, not the statement

Status: accepted

## Context

Privilege escalation in IAM rarely sits in one statement. `iam:PassRole` is harmless alone,
and so is `ec2:RunInstances`, but a principal that holds both can start an instance with an
administrator's role and read its credentials. The two often come from different policies, one
attached to a group and one to the user. A checker that reads statements one at a time cannot
see this.

## Decision

Each user, group and role is judged with all of its identity policies together. A user gets
the policies of every group it is in. For a managed policy, only the default version counts,
because that is the one AWS evaluates. An action is held when some Allow statement covers it,
through `*`, a wildcard or NotAction. An unconditional Deny that covers every resource takes it
away. A conditional Deny does not, because whether it applies is not known.

Escalations are combinations of actions, all of which must be held, from the methods Rhino
Security Labs published in 2018 plus later ones (ECS, CodeBuild, SageMaker, SSM). A method
that passes a role checks `iam:PassedToService`. A role that may only be passed to Lambda
cannot be put on an EC2 instance. On the AWS managed policies this removed 29 of 53
CloudFormation findings and one EC2 finding.

Severity drops a level when the grant is limited to named resources, and again when it holds
only under conditions. A role that may only be updated on one function is less dangerous than
`lambda:UpdateFunctionCode` on `*`. An `iam:PassedToService` condition that names the very
service the method needs limits nothing and is not counted as a condition.

## Consequences

- Findings name the subject and every policy and statement that contributes to them.
- Permission boundaries, service control policies and session policies are not read, and each
  can take away what this tool reports. A finding means "these policies grant it", not
  "this principal can do it today".
- Resource scoping is judged coarsely: "every resource" against "the resources the policy
  names". Whether a named resource is the one that matters (a role that is itself an
  administrator) is not worked out.

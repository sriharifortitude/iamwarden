package policy

import "strings"

// MatchAction reports whether an IAM action pattern ("s3:Get*", "*") matches an action.
// Actions are case-insensitive, and * and ? are the only wildcards.
func MatchAction(pattern, action string) bool {
	return wildcard(strings.ToLower(pattern), strings.ToLower(action))
}

// MatchResource matches an ARN pattern. ARNs are case-sensitive.
func MatchResource(pattern, arn string) bool {
	return wildcard(pattern, arn)
}

// wildcard matches * (any run, including empty) and ? (one character) in linear time with
// one backtrack point, so a hostile pattern cannot make it slow.
func wildcard(p, s string) bool {
	pi, si := 0, 0
	star, mark := -1, 0
	for si < len(s) {
		switch {
		case pi < len(p) && (p[pi] == '?' || p[pi] == s[si]):
			pi++
			si++
		case pi < len(p) && p[pi] == '*':
			star, mark = pi, si
			pi++
		case star >= 0:
			pi = star + 1
			mark++
			si = mark
		default:
			return false
		}
	}
	for pi < len(p) && p[pi] == '*' {
		pi++
	}
	return pi == len(p)
}

// Allows reports whether a statement's action element covers an action: Action matches it,
// or NotAction is set and does not.
func (s Statement) Allows(action string) bool {
	if s.Action != nil {
		for _, p := range s.Action {
			if MatchAction(p, action) {
				return true
			}
		}
		return false
	}
	if s.NotAction != nil {
		for _, p := range s.NotAction {
			if MatchAction(p, action) {
				return false
			}
		}
		return true
	}
	return false
}

// AnyResource reports whether the statement applies to every resource: Resource contains "*",
// or NotResource is set (everything except a list is, for practical purposes, everything).
func (s Statement) AnyResource() bool {
	if s.NotResource != nil {
		return true
	}
	for _, r := range s.Resource {
		if r == "*" {
			return true
		}
	}
	return false
}

// CoversResource reports whether the statement's resource element includes an ARN.
func (s Statement) CoversResource(arn string) bool {
	if s.Resource != nil {
		for _, p := range s.Resource {
			if MatchResource(p, arn) {
				return true
			}
		}
		return false
	}
	if s.NotResource != nil {
		for _, p := range s.NotResource {
			if MatchResource(p, arn) {
				return false
			}
		}
		return true
	}
	return false
}

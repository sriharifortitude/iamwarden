// Package policy reads AWS IAM policy documents, whose JSON allows a string or a list almost
// everywhere, into one regular shape.
package policy

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// Document is a policy document.
type Document struct {
	Version    string
	Statements []Statement
}

// Statement is one statement with its lists normalised.
type Statement struct {
	Sid    string
	Effect string // "Allow" or "Deny"
	// Exactly one of Action and NotAction is set; the same for Resource and NotResource.
	Action      []string
	NotAction   []string
	Resource    []string
	NotResource []string
	// Principal is nil for an identity policy. "*" is stored as {"*": ["*"]}.
	Principal    map[string][]string
	NotPrincipal map[string][]string
	// Condition is operator -> key -> values, keys lower-cased as IAM compares them.
	Condition map[string]map[string][]string
	// Index is the statement's position in the document, from 0.
	Index int
}

// stringOrList accepts "x" or ["x", "y"].
type stringOrList []string

func (s *stringOrList) UnmarshalJSON(b []byte) error {
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		*s = []string{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return fmt.Errorf("expected a string or a list of strings")
	}
	*s = many
	return nil
}

type rawStatement struct {
	Sid          string                     `json:"Sid"`
	Effect       string                     `json:"Effect"`
	Action       *stringOrList              `json:"Action"`
	NotAction    *stringOrList              `json:"NotAction"`
	Resource     *stringOrList              `json:"Resource"`
	NotResource  *stringOrList              `json:"NotResource"`
	Principal    json.RawMessage            `json:"Principal"`
	NotPrincipal json.RawMessage            `json:"NotPrincipal"`
	Condition    map[string]json.RawMessage `json:"Condition"`
}

type rawDocument struct {
	Version   string          `json:"Version"`
	Statement json.RawMessage `json:"Statement"`
}

// Parse reads a policy document. AWS returns documents URL-encoded from some APIs, so a JSON
// string holding an encoded document is decoded first.
func Parse(data []byte) (*Document, error) {
	data = []byte(strings.TrimSpace(string(data)))
	if len(data) > 0 && data[0] == '"' {
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return nil, err
		}
		if decoded, err := url.QueryUnescape(s); err == nil {
			s = decoded
		}
		data = []byte(s)
	}
	var raw rawDocument
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("not a policy document: %v", err)
	}
	if len(raw.Statement) == 0 {
		return nil, fmt.Errorf("not a policy document: no Statement")
	}
	var stmts []rawStatement
	if raw.Statement[0] == '{' {
		var one rawStatement
		if err := json.Unmarshal(raw.Statement, &one); err != nil {
			return nil, fmt.Errorf("Statement: %v", err)
		}
		stmts = []rawStatement{one}
	} else if err := json.Unmarshal(raw.Statement, &stmts); err != nil {
		return nil, fmt.Errorf("Statement: %v", err)
	}
	if len(stmts) == 0 {
		return nil, fmt.Errorf("not a policy document: the Statement list is empty, which AWS refuses")
	}
	doc := &Document{Version: raw.Version}
	for i, r := range stmts {
		s := Statement{Sid: r.Sid, Effect: r.Effect, Index: i}
		if r.Action != nil {
			s.Action = *r.Action
		}
		if r.NotAction != nil {
			s.NotAction = *r.NotAction
		}
		if r.Resource != nil {
			s.Resource = *r.Resource
		}
		if r.NotResource != nil {
			s.NotResource = *r.NotResource
		}
		var err error
		if s.Principal, err = principal(r.Principal); err != nil {
			return nil, fmt.Errorf("statement %d Principal: %v", i, err)
		}
		if s.NotPrincipal, err = principal(r.NotPrincipal); err != nil {
			return nil, fmt.Errorf("statement %d NotPrincipal: %v", i, err)
		}
		if s.Condition, err = conditions(r.Condition); err != nil {
			return nil, fmt.Errorf("statement %d Condition: %v", i, err)
		}
		doc.Statements = append(doc.Statements, s)
	}
	return doc, nil
}

func principal(raw json.RawMessage) (map[string][]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var star string
	if err := json.Unmarshal(raw, &star); err == nil {
		return map[string][]string{star: {star}}, nil
	}
	var m map[string]stringOrList
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("expected \"*\" or an object of principal types")
	}
	out := map[string][]string{}
	for k, v := range m {
		out[k] = v
	}
	return out, nil
}

func conditions(raw map[string]json.RawMessage) (map[string]map[string][]string, error) {
	if raw == nil {
		return nil, nil
	}
	out := map[string]map[string][]string{}
	for op, body := range raw {
		var keys map[string]json.RawMessage
		if err := json.Unmarshal(body, &keys); err != nil {
			return nil, fmt.Errorf("%s: expected an object", op)
		}
		out[op] = map[string][]string{}
		for k, v := range keys {
			var vals stringOrList
			if err := json.Unmarshal(v, &vals); err != nil {
				// Booleans and numbers are allowed unquoted.
				var any interface{}
				if json.Unmarshal(v, &any) != nil {
					return nil, fmt.Errorf("%s %s: unreadable value", op, k)
				}
				if list, ok := any.([]interface{}); ok {
					for _, x := range list {
						vals = append(vals, fmt.Sprint(x))
					}
				} else {
					vals = stringOrList{fmt.Sprint(any)}
				}
			}
			out[op][strings.ToLower(k)] = vals
		}
	}
	return out, nil
}

// ConditionKeys lists the condition keys a statement tests, lower-cased and sorted.
func (s Statement) ConditionKeys() []string {
	seen := map[string]bool{}
	for _, keys := range s.Condition {
		for k := range keys {
			seen[k] = true
		}
	}
	var out []string
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ConditionValues returns the values tested for a key under any operator.
func (s Statement) ConditionValues(key string) []string {
	var out []string
	for _, keys := range s.Condition {
		out = append(out, keys[strings.ToLower(key)]...)
	}
	return out
}

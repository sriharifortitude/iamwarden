// Package cli is iamwarden's command line.
package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/sriharifortitude/iamwarden/internal/policy"
	"github.com/sriharifortitude/iamwarden/internal/rules"
)

// Version is the release.
var Version = "0.1.0"

const maxFileBytes = 64 << 20

const usage = `iamwarden: find AWS IAM permissions that reach further than they look.

usage: iamwarden [flags] PATH...

PATH is a JSON file or a directory of them: a policy document (identity, resource or trust),
the output of "aws iam get-account-authorization-details", or the CLI's wrappers around one
policy (get-policy-version, get-role, get-bucket-policy). - reads standard input.

flags:
  --fail-on LEVEL   exit 1 at or above: critical, high (default), medium, low, info, none
  --json            machine-readable findings
  --version

exit status: 0 nothing at or above --fail-on, 1 at least one finding is, 2 usage error or unreadable input
`

// Run executes the command and returns the exit status.
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("iamwarden", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	failOn := fs.String("fail-on", "high", "")
	asJSON := fs.Bool("json", false, "")
	showVersion := fs.Bool("version", false, "")
	help := fs.Bool("help", false, "")

	var paths []string
	rest := args
	for len(rest) > 0 {
		if err := fs.Parse(rest); err != nil {
			fmt.Fprintf(stderr, "iamwarden: %v\n\n%s", err, usage)
			return 2
		}
		rest = fs.Args()
		if len(rest) > 0 {
			paths = append(paths, rest[0])
			rest = rest[1:]
		}
	}
	switch {
	case *help:
		fmt.Fprint(stdout, usage)
		return 0
	case *showVersion:
		fmt.Fprintf(stdout, "iamwarden %s\n", Version)
		return 0
	case len(paths) == 0:
		fmt.Fprint(stderr, usage)
		return 2
	case *failOn != "none" && rules.Rank(*failOn) == len(rules.Severities):
		fmt.Fprintf(stderr, "iamwarden: --fail-on must be critical, high, medium, low, info or none, not %q\n", *failOn)
		return 2
	}

	var findings []rules.Finding
	read := 0
	for _, p := range paths {
		files, err := expand(p)
		if err != nil {
			fmt.Fprintf(stderr, "iamwarden: %v\n", err)
			return 2
		}
		for _, f := range files {
			data, err := readCapped(f, stdin)
			if err != nil {
				fmt.Fprintf(stderr, "iamwarden: %v\n", err)
				return 2
			}
			in, err := policy.Read(filepath.ToSlash(f), data)
			if err != nil {
				if len(files) == 1 {
					fmt.Fprintf(stderr, "iamwarden: %v\n", err)
					return 2
				}
				findings = append(findings, rules.Finding{ID: "IAM090", Severity: "info", Subject: "input", Message: err.Error()})
				continue
			}
			read++
			findings = append(findings, rules.Check(in)...)
		}
	}

	if *asJSON {
		if findings == nil {
			findings = []rules.Finding{}
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false)
		if err := enc.Encode(map[string]any{"files_read": read, "findings": findings}); err != nil {
			return 2
		}
	} else {
		fmt.Fprint(stdout, Render(read, findings))
	}
	for _, f := range findings {
		if *failOn != "none" && rules.Rank(f.Severity) <= rules.Rank(*failOn) {
			return 1
		}
	}
	return 0
}

func expand(p string) ([]string, error) {
	if p == "-" {
		return []string{"-"}, nil
	}
	info, err := os.Stat(p)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return []string{p}, nil
	}
	var out []string
	err = filepath.WalkDir(p, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.Type().IsRegular() && strings.EqualFold(filepath.Ext(path), ".json") {
			out = append(out, path)
		}
		return nil
	})
	sort.Strings(out)
	return out, err
}

func readCapped(path string, stdin io.Reader) ([]byte, error) {
	var r io.Reader = stdin
	if path != "-" {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		r = f
	}
	data, err := io.ReadAll(io.LimitReader(r, maxFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxFileBytes {
		return nil, fmt.Errorf("%s is over %d MiB", path, maxFileBytes>>20)
	}
	return data, nil
}

// Render formats findings as text, grouped by subject.
func Render(read int, findings []rules.Finding) string {
	var b strings.Builder
	last := ""
	for _, f := range findings {
		if f.Subject != last {
			if last != "" {
				b.WriteByte('\n')
			}
			fmt.Fprintf(&b, "%s\n", f.Subject)
			last = f.Subject
		}
		fmt.Fprintf(&b, "  %s %-8s %s\n", f.ID, f.Severity, f.Message)
		if len(f.Policies) > 0 {
			fmt.Fprintf(&b, "           from %s\n", strings.Join(f.Policies, "; "))
		}
	}
	counts := map[string]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}
	var parts []string
	for _, s := range rules.Severities {
		if counts[s] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[s], s))
		}
	}
	summary := "no findings"
	if len(parts) > 0 {
		summary = strings.Join(parts, ", ")
	}
	if len(findings) > 0 {
		b.WriteByte('\n')
	}
	fmt.Fprintf(&b, "%d file(s) read; %s\n", read, summary)
	return b.String()
}

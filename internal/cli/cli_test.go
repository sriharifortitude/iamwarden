package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func run(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := Run(args, strings.NewReader(stdin), &out, &errb)
	return code, out.String(), errb.String()
}

const td = "../../testdata/"

func TestTheAccountExport(t *testing.T) {
	code, out, _ := run(t, "", td+"account.json")
	if code != 1 || !strings.Contains(out, "role github-deploy") || !strings.Contains(out, "through group developers") ||
		strings.Contains(out, "user auditor") || strings.Contains(out, "batch-worker") {
		t.Fatalf("%d\n%s", code, out)
	}
}

func TestADirectoryIsWalked(t *testing.T) {
	dir := t.TempDir()
	write := func(name, text string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("a.json", `{"Statement":{"Effect":"Allow","Action":"iam:CreateAccessKey","Resource":"*"}}`)
	write("b.json", `{"not":"a policy"}`)
	write("c.txt", `{"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`)
	code, out, _ := run(t, "", dir, "--json")
	var res struct {
		Read     int `json:"files_read"`
		Findings []struct{ ID, Severity, Subject string }
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, f := range res.Findings {
		ids[f.ID] = true
	}
	// a.json is read (escalation, and no Version), b.json is reported as unreadable, c.txt is not .json.
	if code != 1 || res.Read != 1 || len(res.Findings) != 3 || !ids["IAM002"] || !ids["IAM030"] || !ids["IAM090"] {
		t.Fatalf("%d %+v", code, res)
	}
}

func TestStdinAndFailOn(t *testing.T) {
	doc := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:*","Resource":"*"}}`
	for level, want := range map[string]int{"high": 0, "medium": 1, "none": 0} {
		if code, _, _ := run(t, doc, "-", "--fail-on", level); code != want {
			t.Errorf("--fail-on %s: %d", level, code)
		}
	}
}

func TestErrors(t *testing.T) {
	for name, c := range map[string]struct {
		stdin string
		args  []string
	}{
		"no path":       {"", nil},
		"bad fail-on":   {"", []string{"--fail-on", "x", "-"}},
		"unknown flag":  {"", []string{"--nope", "-"}},
		"missing file":  {"", []string{filepath.Join(t.TempDir(), "nope.json")}},
		"one bad file":  {"not json", []string{"-"}},
		"unknown shape": {`{"a":1}`, []string{"-"}},
	} {
		if code, _, errOut := run(t, c.stdin, c.args...); code != 2 || errOut == "" {
			t.Errorf("%s: %d %q", name, code, errOut)
		}
	}
}

func TestVersionAndHelp(t *testing.T) {
	if code, out, _ := run(t, "", "--version"); code != 0 || !strings.HasPrefix(out, "iamwarden ") {
		t.Fatal(out)
	}
	if code, out, _ := run(t, "", "--help"); code != 0 || !strings.Contains(out, "usage:") {
		t.Fatal(out)
	}
}

#!/usr/bin/env bash
# Runs iamwarden over every AWS managed policy, as archived by github.com/z0ph/MAMIP at a fixed
# commit, and checks verdicts that are known independently of this tool. The archive is GPL-3.0,
# so it is fetched here and never copied into this repository.
set -euo pipefail
cd "$(dirname "$0")/.."
BIN=${IAMWARDEN:-./bin/iamwarden}
COMMIT=b37cf396bc24697d660761b61b4b191b8c9cda67
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

git init -q "$tmp/mamip"
git -C "$tmp/mamip" fetch -q --depth 1 https://github.com/z0ph/MAMIP.git "$COMMIT"
git -C "$tmp/mamip" checkout -q FETCH_HEAD -- policies
mkdir "$tmp/managed"
for f in "$tmp"/mamip/policies/*; do cp "$f" "$tmp/managed/$(basename "$f").json"; done

"$BIN" "$tmp/managed" --json --fail-on none > "$tmp/out.json"
python3 - "$tmp/out.json" <<'PY'
import json, sys, collections
d = json.load(open(sys.argv[1]))
by = collections.defaultdict(set)
for f in d["findings"]:
    by[f["subject"].rsplit("/", 1)[-1].removesuffix(".json")].add((f["id"], f["severity"]))
print(f'{d["files_read"]} managed policies read, {len(d["findings"])} findings')
expect = {
    "AdministratorAccess": lambda s: ("IAM001", "critical") in s,
    "IAMFullAccess": lambda s: ("IAM002", "high") in s,
    "PowerUserAccess": lambda s: ("IAM002", "high") in s,          # lambda:UpdateFunctionCode, ssm:SendCommand
    "SecurityAudit": lambda s: not s,
    "ViewOnlyAccess": lambda s: not s,
    "AmazonS3ReadOnlyAccess": lambda s: not s,
    "ReadOnlyAccess": lambda s: not any(i == "IAM002" for i, _ in s),
}
bad = [name for name, ok in expect.items() if not ok(by.get(name, set()))]
for name in expect:
    print(f'  {name:24} {sorted(by.get(name, set())) or "no findings"}')
if bad:
    print("unexpected verdict for:", ", ".join(bad))
    sys.exit(1)
PY

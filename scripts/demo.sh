#!/usr/bin/env bash
# Prints the README's example: the command, then what it prints. Run from anywhere.
set -u
cd "$(dirname "$0")/.."
bin=${IAMWARDEN:-./bin/iamwarden}
echo "\$ iamwarden testdata/account.json testdata/bucket-policy.json"
"$bin" testdata/account.json testdata/bucket-policy.json | tr -d '\r'

// Command iamwarden finds AWS IAM permissions that reach further than they look.
package main

import (
	"os"

	"github.com/sriharifortitude/iamwarden/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

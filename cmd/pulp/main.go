// Command pulp audits a local dev environment for security misconfigurations.
package main

import (
	"fmt"
	"os"
	"runtime/debug"
	"strings"

	"github.com/zonicisalive/pulp/internal/check"
	"github.com/zonicisalive/pulp/internal/explain"

	_ "github.com/zonicisalive/pulp/internal/checks/cors"
	_ "github.com/zonicisalive/pulp/internal/checks/datastore"
	_ "github.com/zonicisalive/pulp/internal/checks/devserver"
	_ "github.com/zonicisalive/pulp/internal/checks/docker"
	_ "github.com/zonicisalive/pulp/internal/checks/gitsec"
	_ "github.com/zonicisalive/pulp/internal/checks/host"
	_ "github.com/zonicisalive/pulp/internal/checks/postgres"
	_ "github.com/zonicisalive/pulp/internal/checks/supply"
)

// version is set at release time: -ldflags "-X main.version=...". For `go install pkg@vX.Y.Z`
// builds (no ldflags) it falls back to the module version recorded in the binary.
var version = "dev"

func init() {
	if bi, ok := debug.ReadBuildInfo(); ok && version == "dev" && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		version = strings.TrimPrefix(bi.Main.Version, "v")
	}
}

const usage = `usage: pulp <command>

  scan [flags] [path]     audit a project and this machine
  staged [path]           scan staged git changes for secrets (used by the hook)
  install-hook [path]     install a git pre-commit hook that runs 'pulp staged'
  baseline [path]         write current findings to .pulp-ignore
  explain <ID>            why a check matters and how to fix it
  list-checks             list all checks
  version`

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, usage)
		return 2
	}
	switch args[0] {
	case "version":
		fmt.Println("pulp", version)
		return 0
	case "list-checks":
		for _, c := range check.All() {
			fmt.Printf("%-10s %-9s %s\n", c.ID(), c.Category(), c.Title())
		}
		return 0
	case "explain":
		return explainCmd(args[1:])
	case "scan":
		return scan(args[1:])
	case "baseline":
		return baseline(args[1:])
	case "staged":
		return staged(args[1:])
	case "install-hook":
		return installHook(args[1:])
	case "help", "-h", "--help":
		fmt.Println(usage)
		return 0
	}
	fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s\n", args[0], usage)
	return 2
}

func explainCmd(args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: pulp explain <ID>")
		return 2
	}
	for _, c := range check.All() {
		if c.ID() == args[0] {
			fmt.Printf("%s  %s\n\n", c.ID(), c.Title())
			if e, ok := explain.Lookup(c.ID()); ok {
				fmt.Printf("Why it matters\n  %s\n\nHow to fix\n  %s\n", e.Why, e.Fix)
			}
			return 0
		}
	}
	fmt.Fprintf(os.Stderr, "unknown check %q (see: pulp list-checks)\n", args[0])
	return 2
}

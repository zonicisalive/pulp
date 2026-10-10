// Package fsutil holds the shared "walk matching files, hand over their lines" helper.
package fsutil

import (
	"bufio"
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
)

// ComposeName matches docker-compose / compose yaml file names.
var ComposeName = regexp.MustCompile(`^(docker-)?compose(\..+)?\.ya?ml$`)

var skipDirs = map[string]bool{".git": true, "node_modules": true, "vendor": true,
	"dist": true, "build": true, "testdata": true, "third_party": true, "site-packages": true, ".venv": true, "venv": true, "__pycache__": true}

const maxFile = 2 << 20 // skip files over 2MB (minified bundles, dumps)

// Walk calls fn for every file and every non-skipped directory under root.
func Walk(ctx context.Context, root string, fn func(rel string, d fs.DirEntry)) {
	filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if ctx.Err() != nil {
			return filepath.SkipAll
		}
		if d.IsDir() && (skipDirs[d.Name()] || (d.Name() == "mod" && filepath.Base(filepath.Dir(p)) == "pkg")) { // GOPATH module cache
			return filepath.SkipDir
		}
		rel, _ := filepath.Rel(root, p)
		fn(rel, d)
		return nil
	})
}

// Files calls fn with the relative path and lines of every file under root whose
// base name satisfies match. Unreadable files are skipped silently.
func Files(ctx context.Context, root string, match func(name string) bool, fn func(rel string, lines []string)) {
	Walk(ctx, root, func(rel string, d fs.DirEntry) {
		if d.IsDir() || !match(d.Name()) {
			return
		}
		if fi, err := d.Info(); err != nil || fi.Size() > maxFile {
			return
		}
		if lines, ok := ReadLines(filepath.Join(root, rel)); ok {
			fn(rel, lines)
		}
	})
}

// ReadLines returns the lines of a file; ok=false if it cannot be read.
func ReadLines(path string) ([]string, bool) {
	f, err := os.Open(path)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	return lines, true
}

// Collect returns the lines of every readable file matching the system globs, plus
// matching files found under root (keyed by relative path).
func Collect(ctx context.Context, root string, sysGlobs []string, match func(string) bool) map[string][]string {
	out := map[string][]string{}
	for _, g := range sysGlobs {
		paths, _ := filepath.Glob(g)
		for _, p := range paths {
			if lines, ok := ReadLines(p); ok {
				out[p] = lines
			}
		}
	}
	Files(ctx, root, match, func(rel string, lines []string) { out[rel] = lines })
	return out
}

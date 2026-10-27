package conventions

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"unicode"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/env"
)

// legacy lists the directories, relative to tests/e2e, exempt from the
// rules while they are migrated. It should stay empty.
var legacy = map[string]bool{}

// exempt lists the directories allowed to call Skip: env.Require is the one
// sanctioned way to skip.
var exempt = map[string]bool{
	"internal/env": true,
}

var serialMarker = regexp.MustCompile(`^//e2e:serial \S`)

// TestConventions enforces the e2e layout rules on every package:
//
//   - a _test.go file holds exactly one top-level Test or Fuzz function and
//     is named after it in snake_case (TestFUSE in fuse_test.go,
//     FuzzTarHeader in fuzz_tar_header_test.go); main_test.go holds only
//     TestMain, and a *_helpers_test.go file holds no test at all;
//   - a top-level test starts with t.Parallel(), unless its file carries an
//     "//e2e:serial <reason>" comment;
//   - nothing calls Skip, Skipf or SkipNow: preconditions go through
//     env.Require so CI can turn them into failures.
func TestConventions(t *testing.T) {
	t.Parallel()
	root, err := env.RepoRoot()
	if err != nil {
		t.Fatal(err)
	}
	e2e := filepath.Join(root, "tests", "e2e")

	fset := token.NewFileSet()
	err = filepath.WalkDir(e2e, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if name := d.Name(); path != e2e && (name == "testdata" || strings.HasPrefix(name, ".")) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		rel, err := filepath.Rel(e2e, path)
		if err != nil {
			return err
		}
		dir := filepath.Dir(rel)
		if legacy[dir] {
			return nil
		}
		file, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if err != nil {
			return err
		}
		if !exempt[dir] {
			checkNoSkip(t, fset, file)
		}
		if strings.HasSuffix(path, "_test.go") {
			checkTestFile(t, fset, rel, file)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func checkTestFile(t *testing.T, fset *token.FileSet, rel string, file *ast.File) {
	t.Helper()
	base := filepath.Base(rel)
	var tests []*ast.FuncDecl
	var hasMain bool
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv != nil {
			continue
		}
		switch {
		case fn.Name.Name == "TestMain":
			hasMain = true
		case isTestFunc(fn):
			tests = append(tests, fn)
		}
	}

	switch {
	case base == "main_test.go":
		if !hasMain || len(tests) > 0 {
			t.Errorf("%s: main_test.go must hold TestMain and nothing else", rel)
		}
		return
	case hasMain:
		t.Errorf("%s: TestMain belongs in main_test.go", rel)
	case strings.HasSuffix(base, "_helpers_test.go"):
		for _, fn := range tests {
			t.Errorf("%s: %s: a helpers file holds no tests", rel, fn.Name.Name)
		}
		return
	}

	if len(tests) != 1 {
		var names []string
		for _, fn := range tests {
			names = append(names, fn.Name.Name)
		}
		t.Errorf("%s: holds %d top-level tests %v, want exactly one (or name it *_helpers_test.go)", rel, len(tests), names)
		return
	}
	fn := tests[0]
	if want := fileName(fn.Name.Name); base != want {
		t.Errorf("%s: %s belongs in %s", rel, fn.Name.Name, want)
	}
	if strings.HasPrefix(fn.Name.Name, "Test") && !hasSerialMarker(file) && !startsWithParallel(fn) {
		t.Errorf("%s: %s must start with t.Parallel(), or the file must say why not with //e2e:serial <reason>",
			fset.Position(fn.Pos()), fn.Name.Name)
	}
}

// isTestFunc reports whether fn is a top-level TestXxx(*testing.T) or
// FuzzXxx(*testing.F).
func isTestFunc(fn *ast.FuncDecl) bool {
	name := fn.Name.Name
	for _, prefix := range []string{"Test", "Fuzz"} {
		rest, ok := strings.CutPrefix(name, prefix)
		if !ok || (rest != "" && unicode.IsLower(rune(rest[0]))) {
			continue
		}
		params := fn.Type.Params.List
		return len(params) == 1 && len(params[0].Names) <= 1
	}
	return false
}

func hasSerialMarker(file *ast.File) bool {
	for _, group := range file.Comments {
		for _, c := range group.List {
			if serialMarker.MatchString(c.Text) {
				return true
			}
		}
	}
	return false
}

func startsWithParallel(fn *ast.FuncDecl) bool {
	if fn.Body == nil || len(fn.Body.List) == 0 {
		return false
	}
	stmt, ok := fn.Body.List[0].(*ast.ExprStmt)
	if !ok {
		return false
	}
	call, ok := stmt.X.(*ast.CallExpr)
	if !ok || len(call.Args) != 0 {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	return ok && sel.Sel.Name == "Parallel"
}

func checkNoSkip(t *testing.T, fset *token.FileSet, file *ast.File) {
	t.Helper()
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
			switch sel.Sel.Name {
			case "Skip", "Skipf", "SkipNow":
				t.Errorf("%s: use env.Require instead of %s", fset.Position(call.Pos()), sel.Sel.Name)
			}
		}
		return true
	})
}

// fileName returns the file a top-level test must live in: the snake_case
// of its name without the Test prefix (Fuzz tests keep a fuzz_ prefix), so
// TestFUSE lives in fuse_test.go and TestTarGNUSparse in
// tar_gnu_sparse_test.go.
func fileName(fn string) string {
	prefix := ""
	name, ok := strings.CutPrefix(fn, "Test")
	if !ok {
		name = strings.TrimPrefix(fn, "Fuzz")
		prefix = "fuzz_"
	}
	return prefix + snake(name) + "_test.go"
}

// snake splits at a lower-to-upper change, and before a capital that starts
// a word after an acronym or a number; digits stay with what precedes them
// (TestD1ReadViaP2P is d1_read_via_p2p).
func snake(s string) string {
	r := []rune(s)
	var b strings.Builder
	for i, c := range r {
		if i > 0 && unicode.IsUpper(c) {
			prev := r[i-1]
			nextLower := i+1 < len(r) && unicode.IsLower(r[i+1])
			if unicode.IsLower(prev) || ((unicode.IsUpper(prev) || unicode.IsDigit(prev)) && nextLower) {
				b.WriteByte('_')
			}
		}
		if c == '_' {
			if !strings.HasSuffix(b.String(), "_") {
				b.WriteByte('_')
			}
			continue
		}
		b.WriteRune(unicode.ToLower(c))
	}
	return b.String()
}

package gosec

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestUnitFilterOutGeneratedGoFiles(t *testing.T) {
	f, err := os.Open("./testdata")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	fiL, err := f.Readdir(-1)
	if err != nil {
		t.Fatal(err)
	}

	goFiles := make([]string, 0, 10)
	for _, fi := range fiL {
		if !fi.IsDir() && strings.HasSuffix(fi.Name(), ".go") {
			goFiles = append(goFiles, filepath.Join(f.Name(), fi.Name()))
		}
	}

	filtered := filterOutGeneratedGoFiles(goFiles)
	want := []string{
		"testdata/without_generated_header.go",
                "testdata/with_cgo_import_no_generated_code.go",
                "testdata/with_regular_code_comment_about_generated.go",
	}
	if diff := cmp.Diff(filtered, want); diff != "" {
		t.Fatalf("Result mismatch: got - want +\n%s", diff)
	}
}

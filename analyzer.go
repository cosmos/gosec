// (c) Copyright 2016 Hewlett Packard Enterprise Development LP
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package gosec holds the central scanning logic used by gosec security scanner
package gosec

import (
	"fmt"
	"go/ast"
	"go/build"
	"go/token"
	"go/types"
	"log"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime" // #nosec
	"sort"
	"strconv"
	"sync"

	"strings"

	"golang.org/x/tools/go/packages"
)

// LoadMode controls the amount of details to return when loading the packages
const LoadMode = packages.NeedName |
	packages.NeedFiles |
	packages.NeedCompiledGoFiles |
	packages.NeedImports |
	packages.NeedTypes |
	packages.NeedTypesSizes |
	packages.NeedTypesInfo |
	packages.NeedSyntax

// The Context is populated with data parsed from the source code as it is scanned.
// It is passed through to all rule functions as they are called. Rules may use
// this data in conjunction withe the encountered AST node.
type Context struct {
	FileSet      *token.FileSet
	Comments     ast.CommentMap
	Info         *types.Info
	Pkg          *types.Package
	PkgFiles     []*ast.File
	Root         *ast.File
	Config       Config
	Imports      *ImportTracker
	Ignores      []map[string]bool
	PassedValues map[string]interface{}
}

// Metrics used when reporting information about a scanning run.
type Metrics struct {
	NumFiles int `json:"files"`
	NumLines int `json:"lines"`
	NumNosec int `json:"nosec"`
	NumFound int `json:"found"`
}

// Analyzer object is the main object of gosec. It has methods traverse an AST
// and invoke the correct checking rules as on each node as required.
type Analyzer struct {
	ignoreNosec bool
	ruleset     RuleSet
	context     *Context
	config      Config
	logger      *log.Logger
	issues      []*Issue
	stats       *Metrics
	errors      map[string][]Error // keys are file paths; values are the golang errors in those files
	tests       bool
}

// NewAnalyzer builds a new analyzer.
func NewAnalyzer(conf Config, tests bool, logger *log.Logger) *Analyzer {
	ignoreNoSec := false
	if enabled, err := conf.IsGlobalEnabled(Nosec); err == nil {
		ignoreNoSec = enabled
	}
	if logger == nil {
		logger = log.New(os.Stderr, "[gosec]", log.LstdFlags)
	}
	return &Analyzer{
		ignoreNosec: ignoreNoSec,
		ruleset:     make(RuleSet),
		context:     &Context{},
		config:      conf,
		logger:      logger,
		issues:      make([]*Issue, 0, 16),
		stats:       &Metrics{},
		errors:      make(map[string][]Error),
		tests:       tests,
	}
}

// SetConfig upates the analyzer configuration
func (gosec *Analyzer) SetConfig(conf Config) {
	gosec.config = conf
}

// Config returns the current configuration
func (gosec *Analyzer) Config() Config {
	return gosec.config
}

// LoadRules instantiates all the rules to be used when analyzing source
// packages
func (gosec *Analyzer) LoadRules(ruleDefinitions map[string]RuleBuilder) {
	ids := make([]string, 0, len(ruleDefinitions))
	for id := range ruleDefinitions {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })

	for _, id := range ids {
		def := ruleDefinitions[id]
		r, nodes := def(id, gosec.config)
		gosec.ruleset.Register(r, nodes...)
	}
}

// Process kicks off the analysis process for a given package
func (gosec *Analyzer) Process(buildTags []string, packagePaths ...string) error {
	config := &packages.Config{
		Mode:       LoadMode,
		BuildFlags: buildTags,
		Tests:      gosec.tests,
	}

	for _, pkgPath := range packagePaths {
		pkgs, err := gosec.load(pkgPath, config)
		if err != nil {
			gosec.AppendError(pkgPath, err)
		}
		for _, pkg := range pkgs {
			if pkg.Name != "" {
				err := gosec.ParseErrors(pkg)
				if err != nil {
					return fmt.Errorf("parsing errors in pkg %q: %v", pkg.Name, err)
				}
				gosec.Check(pkg)
			}
		}
	}
	sortErrors(gosec.errors)
	return nil
}

var reGeneratedGoFile = regexp.MustCompile(`^// Code generated .* DO NOT EDIT\.`)

// filterOutGeneratedGoFiles parallelizes the proocess of checking the contents
// of the files in fullPaths for the presence of generated Go headers to avoid
// reporting on generated code, per https://github.com/cosmos/gosec/issues/30
func filterOutGeneratedGoFiles(fullPaths []string) (filtered []string) {
	if len(fullPaths) == 0 {
		return nil
	}

	if len(fullPaths) == 1 {
		blob, err := os.ReadFile(fullPaths[0])
		if err != nil {
			panic(err)
		}
		if !reGeneratedGoFile.Match(blob) {
			filtered = append(filtered, fullPaths[0])
		}
		return
	}

	// position stores the order "pos" which will later be
	// used to sort the paths to maintain original order
	// despite the concurrent filtering that'll take place.
	type position struct {
		pos      int
		fullPath string
	}

	posCh := make(chan *position, 10)
	go func() {
		defer close(posCh)
		for i, fullPath := range fullPaths {
			posCh <- &position{pos: i, fullPath: fullPath}
		}
	}()

	filteredCh := make(chan *position, 10)
	var wg sync.WaitGroup
	// Spin up NumCPU goroutines that'll each open up a file
	// for as long as there is one to be read on posCh.
	for i := 0; i < runtime.NumCPU(); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for pi := range posCh {
				blob, err := os.ReadFile(pi.fullPath)
				if err != nil {
					panic(err)
				}
				if !reGeneratedGoFile.Match(blob) {
					filteredCh <- pi
				}
			}
		}()
	}

	go func() {
		wg.Wait()
		close(filteredCh)
	}()

	ordered := make([]*position, 0, len(fullPaths))
	for nonGeneratedGoFilePath := range filteredCh {
		ordered = append(ordered, nonGeneratedGoFilePath)
	}
	sort.Slice(ordered, func(i, j int) bool {
		oi, oj := ordered[i], ordered[j]
		return oi.pos < oj.pos
	})

	filtered = make([]string, 0, len(ordered))
	for _, oi := range ordered {
		filtered = append(filtered, oi.fullPath)
	}
	return filtered
}

func (gosec *Analyzer) load(pkgPath string, conf *packages.Config) ([]*packages.Package, error) {
	abspath, err := GetPkgAbsPath(pkgPath)
	if err != nil {
		gosec.logger.Printf("Skipping: %s. Path doesn't exist.", abspath)
		return []*packages.Package{}, nil
	}

	gosec.logger.Println("Import directory:", abspath)

	// Find the deepest go.mod for the package, defaulting to the working directory.
	absWorkingDir, err := GetPkgAbsPath(".")
	if err != nil {
		return nil, err
	}
	absGoModPath := absWorkingDir
	for p := abspath; p != absWorkingDir; p = filepath.Dir(p) {
		if info, err := os.Stat(filepath.Join(p, "go.mod")); err == nil && !info.IsDir() {
			absGoModPath = p
			break
		}
		// Break out if we've reached the root directory.
		if strings.HasSuffix(p, string(filepath.Separator)) {
			break
		}
	}

	// step 1/3: create build context.
	buildD := build.Default
	// step 2/3: add build tags to get env dependent files into basePackage.
	buildD.BuildTags = conf.BuildFlags
	buildD.Dir = absGoModPath
	basePackage, err := buildD.ImportDir(abspath, build.ImportComment)
	if err != nil {
		return []*packages.Package{}, fmt.Errorf("importing dir %q: %v", pkgPath, err)
	}

	var packageFiles []string
	for _, filename := range basePackage.GoFiles {
		packageFiles = append(packageFiles, path.Join(abspath, filename))
	}

	for _, filename := range basePackage.CgoFiles {
		packageFiles = append(packageFiles, path.Join(abspath, filename))
	}

	if gosec.tests {
		testsFiles := []string{}
		testsFiles = append(testsFiles, basePackage.TestGoFiles...)
		testsFiles = append(testsFiles, basePackage.XTestGoFiles...)
		for _, filename := range testsFiles {
			packageFiles = append(packageFiles, path.Join(abspath, filename))
		}
	}

	// step 3/3: remove build tags from conf to proceed build correctly.
	conf.BuildFlags = nil
	conf.Dir = absGoModPath
	pkgs, err := packages.Load(conf, packageFiles...)
	if err != nil {
		return []*packages.Package{}, fmt.Errorf("loading files from package %q: %v", pkgPath, err)
	}
	return pkgs, nil
}

func underTestUtilDirOrPath(path string) bool {
	splits := strings.Split(path, string(filepath.Separator))
	for _, split := range splits {
		if split == "testutil" {
			return true
		}
	}
	return false
}

// Check runs analysis on the given package
func (gosec *Analyzer) Check(pkg *packages.Package) {
	gosec.logger.Println("Checking package:", pkg.Name)

	for _, file := range pkg.Syntax {
		checkedFile := pkg.Fset.File(file.Pos()).Name()
		// Skip the no-Go file from analysis (e.g. a Cgo files is expanded in 3 different files
		// stored in the cache which do not need to by analyzed)
		if filepath.Ext(checkedFile) != ".go" {
			continue
		}

		// Skip over analyzing files in */testutil/* as they are causing spurious failures yet don't return
		// much value in vulnerability reports. Please see https://github.com/cosmos/gosec/issues/52
		if underTestUtilDirOrPath(checkedFile) {
			continue
		}

		gosec.logger.Println("Checking file:", checkedFile)
		gosec.context.FileSet = pkg.Fset
		gosec.context.Config = gosec.config
		gosec.context.Comments = ast.NewCommentMap(gosec.context.FileSet, file, file.Comments)
		gosec.context.Root = file
		gosec.context.Info = pkg.TypesInfo
		gosec.context.Pkg = pkg.Types
		gosec.context.PkgFiles = pkg.Syntax
		gosec.context.Imports = NewImportTracker()
		gosec.context.Imports.TrackFile(file)
		gosec.context.PassedValues = make(map[string]interface{})

		// Only walk non-generated Go files as we definitely don't
		// want to report on generated code, which is out of our direct control.
		// Please see: https://github.com/cosmos/gosec/issues/30
		if filtered := filterOutGeneratedGoFiles([]string{checkedFile}); len(filtered) > 0 {
			ast.Walk(gosec, file)
		}
		gosec.stats.NumFiles++
		gosec.stats.NumLines += pkg.Fset.File(file.Pos()).LineCount()
	}
}

// ParseErrors parses the errors from given package
func (gosec *Analyzer) ParseErrors(pkg *packages.Package) error {
	if len(pkg.Errors) == 0 {
		return nil
	}
	for _, pkgErr := range pkg.Errors {
		parts := strings.Split(pkgErr.Pos, ":")
		file := parts[0]
		var err error
		var line int
		if len(parts) > 1 {
			if line, err = strconv.Atoi(parts[1]); err != nil {
				return fmt.Errorf("parsing line: %v", err)
			}
		}
		var column int
		if len(parts) > 2 {
			if column, err = strconv.Atoi(parts[2]); err != nil {
				return fmt.Errorf("parsing column: %v", err)
			}
		}
		msg := strings.TrimSpace(pkgErr.Msg)
		newErr := NewError(line, column, msg)
		if errSlice, ok := gosec.errors[file]; ok {
			gosec.errors[file] = append(errSlice, *newErr)
		} else {
			errSlice = []Error{}
			gosec.errors[file] = append(errSlice, *newErr)
		}
	}
	return nil
}

// AppendError appends an error to the file errors
func (gosec *Analyzer) AppendError(file string, err error) {
	// Do not report the error for empty packages (e.g. files excluded from build with a tag)
	r := regexp.MustCompile(`no buildable Go source files in`)
	if r.MatchString(err.Error()) {
		return
	}
	errors := []Error{}
	if ferrs, ok := gosec.errors[file]; ok {
		errors = ferrs
	}
	ferr := NewError(0, 0, err.Error())
	errors = append(errors, *ferr)
	gosec.errors[file] = errors
}

// ignore a node (and sub-tree) if it is tagged with a nosec tag comment
func (gosec *Analyzer) ignore(n ast.Node) ([]string, bool) {
	if groups, ok := gosec.context.Comments[n]; ok && !gosec.ignoreNosec {

		// Checks if an alternative for #nosec is set and, if not, uses the default.
		noSecDefaultTag := "#nosec"
		noSecAlternativeTag, err := gosec.config.GetGlobal(NoSecAlternative)
		if err != nil {
			noSecAlternativeTag = noSecDefaultTag
		}

		for _, group := range groups {

			foundDefaultTag := strings.Contains(group.Text(), noSecDefaultTag)
			foundAlternativeTag := strings.Contains(group.Text(), noSecAlternativeTag)

			if foundDefaultTag || foundAlternativeTag {
				gosec.stats.NumNosec++

				// Pull out the specific rules that are listed to be ignored.
				re := regexp.MustCompile(`(G\d{3})`)
				matches := re.FindAllStringSubmatch(group.Text(), -1)

				// If no specific rules were given, ignore everything.
				if len(matches) == 0 {
					return nil, true
				}

				// Find the rule IDs to ignore.
				var ignores []string
				for _, v := range matches {
					ignores = append(ignores, v[1])
				}
				return ignores, false
			}
		}
	}
	return nil, false
}

// Visit runs the gosec visitor logic over an AST created by parsing go code.
// Rule methods added with AddRule will be invoked as necessary.
func (gosec *Analyzer) Visit(n ast.Node) ast.Visitor {
	// If we've reached the end of this branch, pop off the ignores stack.
	if n == nil {
		if len(gosec.context.Ignores) > 0 {
			gosec.context.Ignores = gosec.context.Ignores[1:]
		}
		return gosec
	}

	// Get any new rule exclusions.
	ignoredRules, ignoreAll := gosec.ignore(n)
	if ignoreAll {
		return nil
	}

	// Now create the union of exclusions.
	ignores := map[string]bool{}
	if len(gosec.context.Ignores) > 0 {
		for k, v := range gosec.context.Ignores[0] {
			ignores[k] = v
		}
	}

	for _, v := range ignoredRules {
		ignores[v] = true
	}

	// Push the new set onto the stack.
	gosec.context.Ignores = append([]map[string]bool{ignores}, gosec.context.Ignores...)

	// Track aliased and initialization imports
	gosec.context.Imports.TrackImport(n)

	for _, rule := range gosec.ruleset.RegisteredFor(n) {
		if _, ok := ignores[rule.ID()]; ok {
			continue
		}
		issue, err := rule.Match(n, gosec.context)
		if err != nil {
			file, line := GetLocation(n, gosec.context)
			file = path.Base(file)
			gosec.logger.Printf("Rule error: %T => %s (%s:%d)\n", rule, err, file, line)
		}
		if issue != nil {
			gosec.issues = append(gosec.issues, issue)
			gosec.stats.NumFound++
		}
	}
	return gosec
}

// Report returns the current issues discovered and the metrics about the scan
func (gosec *Analyzer) Report() ([]*Issue, *Metrics, map[string][]Error) {
	return gosec.issues, gosec.stats, gosec.errors
}

// Reset clears state such as context, issues and metrics from the configured analyzer
func (gosec *Analyzer) Reset() {
	gosec.context = &Context{}
	gosec.issues = make([]*Issue, 0, 16)
	gosec.stats = &Metrics{}
	gosec.ruleset = NewRuleSet()
}

package output

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/cosmos/gosec/v2"
)

type sarifLevel string

const (
	sarifNone    = sarifLevel("none")
	sarifNote    = sarifLevel("note")
	sarifWarning = sarifLevel("warning")
	sarifError   = sarifLevel("error")
)

type sarifProperties struct {
	Tags []string `json:"tags"`
}

type sarifRule struct {
	ID                   string              `json:"id"`
	Name                 string              `json:"name"`
	ShortDescription     *sarifMessage       `json:"shortDescription"`
	FullDescription      *sarifMessage       `json:"fullDescription"`
	Help                 *sarifMessage       `json:"help"`
	Properties           *sarifProperties    `json:"properties"`
	DefaultConfiguration *sarifConfiguration `json:"defaultConfiguration"`
}

type sarifConfiguration struct {
	Level sarifLevel `json:"level"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine   uint64 `json:"startLine"`
	EndLine     uint64 `json:"endLine"`
	StartColumn uint64 `json:"startColumn"`
	EndColumn   uint64 `json:"endColumn"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation *sarifArtifactLocation `json:"artifactLocation"`
	Region           *sarifRegion           `json:"region"`
}

type sarifLocation struct {
	PhysicalLocation *sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string           `json:"ruleId"`
	RuleIndex int              `json:"ruleIndex"`
	Level     sarifLevel       `json:"level"`
	Message   *sarifMessage    `json:"message"`
	Locations []*sarifLocation `json:"locations"`
}

type sarifDriver struct {
	Name           string       `json:"name"`
	Version        string       `json:"version"`
	InformationURI string       `json:"informationUri"`
	Rules          []*sarifRule `json:"rules,omitempty"`
}

type sarifTool struct {
	Driver *sarifDriver `json:"driver"`
}

type sarifRun struct {
	Tool    *sarifTool     `json:"tool"`
	Results []*sarifResult `json:"results"`
}

type sarifReport struct {
	Schema  string      `json:"$schema"`
	Version string      `json:"version"`
	Runs    []*sarifRun `json:"runs"`
}

// buildSarifReport return SARIF report struct
func buildSarifReport() *sarifReport {
	return &sarifReport{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs:    []*sarifRun{},
	}
}

// buildSarifRule return SARIF rule field struct
func buildSarifRule(issue *gosec.Issue) *sarifRule {
	return &sarifRule{
		ID:   fmt.Sprintf("%s (CWE-%s)", issue.RuleID, issue.Cwe.ID),
		Name: issue.What,
		ShortDescription: &sarifMessage{
			Text: issue.What,
		},
		FullDescription: &sarifMessage{
			Text: issue.What,
		},
		Help: &sarifMessage{
			Text: fmt.Sprintf("%s\nSeverity: %s\nConfidence: %s\nCWE: %s", issue.What, issue.Severity.String(), issue.Confidence.String(), issue.Cwe.URL),
		},
		Properties: &sarifProperties{
			Tags: []string{fmt.Sprintf("CWE-%s", issue.Cwe.ID), issue.Severity.String()},
		},
		DefaultConfiguration: &sarifConfiguration{
			Level: getSarifLevel(issue.Severity.String()),
		},
	}
}

// buildSarifLocation return SARIF location struct
func buildSarifLocation(issue *gosec.Issue, rootPaths []string) (*sarifLocation, error) {
	var filePath string

	lines := strings.Split(issue.Line, "-")
	startLine, err := strconv.ParseUint(lines[0], 10, 64)
	if err != nil {
		return nil, err
	}
	endLine := startLine
	if len(lines) > 1 {
		endLine, err = strconv.ParseUint(lines[1], 10, 64)
		if err != nil {
			return nil, err
		}
	}

	col, err := strconv.ParseUint(issue.Col, 10, 64)
	if err != nil {
		return nil, err
	}

	for _, rootPath := range rootPaths {
		if strings.HasPrefix(issue.File, rootPath) {
			filePath = strings.Replace(issue.File, rootPath+"/", "", 1)
		}
	}

	location := &sarifLocation{
		PhysicalLocation: &sarifPhysicalLocation{
			ArtifactLocation: &sarifArtifactLocation{
				URI: filePath,
			},
			Region: &sarifRegion{
				StartLine:   startLine,
				EndLine:     endLine,
				StartColumn: col,
				EndColumn:   col,
			},
		},
	}

	return location, nil
}

// From https://docs.oasis-open.org/sarif/sarif/v2.0/csprd02/sarif-v2.0-csprd02.html#_Toc10127839
// * "warning": The rule specified by ruleId was evaluated and a problem was found.
// * "error": The rule specified by ruleId was evaluated and a serious problem was found.
// * "note": The rule specified by ruleId was evaluated and a minor problem or an opportunity to improve the code was found.
func getSarifLevel(s string) sarifLevel {
	switch s {
	case "LOW":
		return sarifWarning
	case "MEDIUM":
		return sarifError
	case "HIGH":
		return sarifError
	default:
		return sarifNote
	}
}

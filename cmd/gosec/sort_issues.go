package main

import (
	"sort"
	"strconv"
	"strings"

	"github.com/informalsystems/gosec/v2"
)

// handle ranges
func extractLineNumber(s string) int {
	lineNumber, err := strconv.Atoi(strings.Split(s, "-")[0])
	if err != nil {
		// TODO: Should this panic?
		lineNumber = 0
	}
	return lineNumber

}

type sortBySeverity []*gosec.Issue

func (s sortBySeverity) Len() int { return len(s) }

func (s sortBySeverity) Less(i, j int) bool {
	if s[i].Severity != s[j].Severity {
		return s[i].Severity > s[j].Severity
	}

	if s[i].What != s[j].What {
		return s[i].What > s[j].What
	}

	if s[i].File == s[j].File {
		return extractLineNumber(s[i].Line) > extractLineNumber(s[j].Line)
	}
	return s[i].File > s[j].File
}

func (s sortBySeverity) Swap(i, j int) { s[i], s[j] = s[j], s[i] }

// sortIssues sorts the issues by severity in descending order
func sortIssues(issues []*gosec.Issue) {
	sort.Sort(sortBySeverity(issues))
}

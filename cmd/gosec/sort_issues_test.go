package main

import (
	"testing"

	"github.com/informalsystems/gosec/v2"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var defaultIssue = gosec.Issue{
	File:       "/home/src/project/test.go",
	Line:       "1",
	Col:        "1",
	RuleID:     "ruleID",
	What:       "test",
	Confidence: gosec.High,
	Severity:   gosec.High,
	Code:       "1: testcode",
	Cwe:        gosec.GetCwe("G101"),
}

func createIssue() gosec.Issue {
	return defaultIssue
}

func TestRules(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Sort issues Suite")
}

func firstIsGreater(less, greater *gosec.Issue) {
	slice := []*gosec.Issue{less, greater}

	sortIssues(slice)

	ExpectWithOffset(0, slice[0]).To(Equal(greater))
}

var _ = Describe("Sorting by Severity", func() {
	It("sortes by severity", func() {
		less := createIssue()
		less.Severity = gosec.Low
		greater := createIssue()
		less.Severity = gosec.High
		firstIsGreater(&less, &greater)
	})

	Context("Serverity is same", func() {
		It("sortes by What", func() {
			less := createIssue()
			less.What = "test1"
			greater := createIssue()
			greater.What = "test2"
			firstIsGreater(&less, &greater)
		})
	})

	Context("Serverity and What is same", func() {
		It("sortes by File", func() {
			less := createIssue()
			less.File = "test1"
			greater := createIssue()
			greater.File = "test2"

			firstIsGreater(&less, &greater)
		})
	})

	Context("Serverity, What and File is same", func() {
		It("sortes by line number", func() {
			less := createIssue()
			less.Line = "1"
			greater := createIssue()
			greater.Line = "2"

			firstIsGreater(&less, &greater)
		})
	})
})

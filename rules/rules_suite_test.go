package rules_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"testing"
)

func TestRules(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Rules Suite")
}

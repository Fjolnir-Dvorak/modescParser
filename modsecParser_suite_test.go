package main_test

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestModsecParser(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "ModsecParser Suite")
}

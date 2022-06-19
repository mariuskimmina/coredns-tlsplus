package tls

import (
	"fmt"
	"testing"
)

func TestNewCertmagicConfig(t *testing.T) {
	var testTable = []struct {
		name string
	}{
		{
			name: "Happy TestCase",
		},
	}

	for _, e := range testTable {
		fmt.Println(e.name)
		certmagicConfig := NewCertmagicConfig()
		fmt.Println(certmagicConfig)
	}
}

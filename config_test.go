package tls

import (
	"fmt"
	"testing"

	"github.com/coredns/coredns/core/dnsserver"
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
        config := &dnsserver.Config{}
        certmagicConfig := NewCertmagicConfig(config)
        fmt.Println(certmagicConfig)
    }
}

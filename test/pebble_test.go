package test

import (
	"fmt"
	"os"
	"testing"
	//"time"
)

func TestWithPebble(t *testing.T) {
	// TODO: there should be a better way to do this
	// removing the certmagic dir, so that certmagic does
	// not try to use exisiting accounts  from previous tests
	err := os.RemoveAll("/home/marius/.local/share/certmagic")
	if err != nil {
		fmt.Println("Nothing to remove in certmagic")
	}

	resolverAddress := "127.0.0.1:1053"
	go func() {
		PebbleServer(resolverAddress)
	}()

	corefile := `.:1053 {
        tls acme {
            domain example.com
        }
        whoami
	}`
	ex, _, _, err := CoreDNSServerAndPorts(corefile)
	if err != nil {
		t.Fatalf("Could not get CoreDNS serving instance: %s", err)
	}
	defer ex.Stop()

	if err != nil {
		t.Errorf("Failed to kill pebble: %v", err)
	}
}

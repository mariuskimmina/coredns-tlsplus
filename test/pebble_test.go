package test

import (
	//"os/exec"
	"testing"
	"time"
)

func TestWithPebble(t *testing.T) {
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

	time.Sleep(5 * time.Second)
	//err = cmd.Process.Kill()
	if err != nil {
		t.Errorf("Failed to kill pebble: %v", err)
	}
}

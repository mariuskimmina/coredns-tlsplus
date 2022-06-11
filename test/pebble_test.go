package test

import (
	"os/exec"
	"testing"
	"time"
)

func TestWithPebble(t *testing.T) {
	binary := "pebble"
	arg0 := "-dnsserver"
	arg1 := "127.0.0.1:1053"
	cmd := exec.Command(binary, arg0, arg1)
	go func() {
		err := cmd.Start()
		if err != nil {
			t.Errorf("Failed to run pebble: %v", err)
		}
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

	time.Sleep(2 * time.Second)
	err = cmd.Process.Kill()
	if err != nil {
		t.Errorf("Failed to kill pebble: %v", err)
	}
}

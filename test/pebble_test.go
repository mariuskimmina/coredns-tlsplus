package test

import (
	"os"
	"testing"
	//"time"
)

func TestCorefile(t *testing.T) {
	certmagicDataPath := "/home/marius/.local/share/certmagic"
	testcases := []struct {
		name            string
		config          string
		resolverAddress string
	}{
		{
			name: "LocalAddr",
			config: `.:1053 {
                tls acme {
                    domain example.com
                }
                whoami
            }`,
			resolverAddress: "127.0.0.1:1053",
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			go func() {
				// todo: start and shutdown
				PebbleServer(tc.resolverAddress)
			}()
			if err := os.RemoveAll(certmagicDataPath); err != nil {
				t.Logf("Nothing to remove in %q", certmagicDataPath)
			}

			ex, _, _, err := CoreDNSServerAndPorts(tc.config)
			if err != nil {
				t.Fatalf("Could not get CoreDNS serving instance: %s", err)
			}
			defer ex.Stop()
		})
	}
}

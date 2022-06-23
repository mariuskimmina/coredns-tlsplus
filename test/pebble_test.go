package test

import (
	"crypto/tls"
	"fmt"
	"os"
	"testing"

	//"time"

	"github.com/miekg/dns"
)

func TestCorefile(t *testing.T) {
	certmagicDataPath := "/home/marius/.local/share/certmagic"
	testcases := []struct {
		name            string
		config          string
		resolverAddress string
        Qname           string
        Qtype           uint16 
        Answer          []dns.RR
	}{
		{
			name: "LocalAddr",
			config: `.:1053 {
                tls acme {
                    domain example.com
                }
                forward . 8.8.8.8
            }`,
			resolverAddress: "127.0.0.1:1053",
            Qname: "example.org.",
            Qtype: dns.TypeA,
            Answer: nil,
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

			ex, _, tcp, err := CoreDNSServerAndPorts(tc.config)
			if err != nil {
				t.Fatalf("Could not get CoreDNS serving instance: %s", err)
			}
			defer ex.Stop()
            fmt.Println("CoreDNS Server should now be ready for DNS requests")

            m := new(dns.Msg)
			m.SetQuestion(tc.Qname, tc.Qtype)
			m.SetEdns0(4096, true)
            client := dns.Client{
                Net: "tcp-tls",
                TLSConfig: &tls.Config{InsecureSkipVerify: true},
            }
            r, _, err := client.Exchange(m, tcp)

			if err != nil {
				t.Fatalf("Could not exchange msg: %s", err)
			}
            //if n := len(r.Answer); n != len(tc.Answer) {
				//t.Fatalf("Expected %v answers, got %v", len(tc.Answer), n)
			//}
            fmt.Println(r.Answer)
            fmt.Println(r.String())
            t.Error()

		})
	}
}

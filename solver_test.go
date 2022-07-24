package tls

import (
	"fmt"
	"net"
	"testing"

	"github.com/mholt/acmez/acme"
	"github.com/miekg/dns"
)

func setupACME(readyChan chan string) {
	acmeServer := &ACMEServer{
		readyChan: readyChan,
	}
	addr := net.UDPAddr{
		Port: 2053,
		IP:   net.ParseIP("0.0.0.0"),
	}

	l, err := net.ListenUDP("udp", &addr)
	if err != nil {
		fmt.Println(err)
	}
	go func() {
		challenge := acme.Challenge{}
		err := acmeServer.Start(l, challenge)
		if err != nil {
			fmt.Println(err)
		}
	}()
	return
}

func TestSolveChallenge(t *testing.T) {
	testcases := []struct {
		name     string
		question string
	}{
		{
			name:     "ACME Challenge",
			question: "_acme-challenge.example.com.",
		},
	}
	readyChan := make(chan string)
	setupACME(readyChan)
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			ready := <-readyChan
			fmt.Println(ready)

			m := new(dns.Msg)
			m.SetQuestion(tc.question, dns.TypeTXT)
			resp, err := dns.Exchange(m, "127.0.0.1:2053")
			if err != nil {
				t.Fatalf("Expected to receive reply, but didn't: %v", err)
			}
			if len(resp.Answer) == 0 {
				t.Fatalf("Expected to at least one RR in the answer section, got none")
			}

		})
	}
}

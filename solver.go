package tls

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/coredns/coredns/request"
	"github.com/mholt/acmez/acme"
	"github.com/miekg/dns"
)

type DNSSolver struct {
	Port int
	Addr string
	DNS  *ACMEServer
}

type ACMEServer struct {
	m         sync.Mutex  // protects the servers
	server    *dns.Server // 0 is a net.Listener, 1 is a net.PacketConn (a *UDPConn) in our case.
	readyChan chan string
}

func (as *ACMEServer) Start(p net.PacketConn, challenge acme.Challenge) error {
	as.m.Lock()
	as.server = &dns.Server{PacketConn: p, Net: "udp", Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		acme_request := true
		state := request.Request{W: w, Req: r}
		hdr := dns.RR_Header{Name: state.QName(), Rrtype: dns.TypeTXT, Class: dns.ClassANY, Ttl: 0}
		m := new(dns.Msg)
		m.SetReply(r)
		if state.QType() != dns.TypeTXT {
			fmt.Println("Received Wrong DNS Request")
			acme_request = false
		}
            
		if !checkDNSChallenge(state.Name()) {
			fmt.Println("Received Something else, ignoring")
			acme_request = false
        }

		if !acme_request {
			fmt.Println("Ignoring DNS request:", state.Name())
            return
		} 

        log.Debug("Answering DNS request:", state.Name())
        m.Answer = append(m.Answer, &dns.TXT{Hdr: hdr, Txt: []string{challenge.DNS01KeyAuthorization()}})
        w.WriteMsg(m)
        return
	})}
	as.m.Unlock()

	as.readyChan <- "ready"
	return as.server.ActivateAndServe()
}

func (as *ACMEServer) ShutDown() error {
	err := as.server.Shutdown()
	return err
}

const (
	dnsChallengeString   = "_acme-challenge."
	pluginName           = "tlsplus"
)

func checkDNSChallenge(zone string) bool {
	return strings.HasPrefix(zone, dnsChallengeString)
}

// Present is called just before a challenge is initiated.
// The implementation MUST prepare anything that is necessary
// for completing the challenge
// for CoreDNS that means that we need to start the DNS Server,
// serve exactly one request and
func (d *DNSSolver) Present(ctx context.Context, challenge acme.Challenge) error {

	readyChan := make(chan string)
	acmeServer := &ACMEServer{
		readyChan: readyChan,
	}
	d.DNS = acmeServer

	addr := net.UDPAddr{
		Port: d.Port,
		IP:   net.ParseIP("0.0.0.0"),
	}

	l, err := net.ListenUDP("udp", &addr)
	if err != nil {
		fmt.Println("Failed to create Listener")
		fmt.Println(err)
	}

	if err != nil {
		fmt.Println("Failed to create Listener")
		fmt.Println(err)
	}

	go func() {
		err := d.DNS.Start(l, challenge)
		if err != nil {
			fmt.Println("Received Error from ServePacket")
			fmt.Println(err)
		}
	}()
	return nil
}

func (d *DNSSolver) Wait(ctx context.Context, challenge acme.Challenge) error {
	select {
	case <-d.DNS.readyChan:
        return nil
	case <-time.After(4 * time.Second):
		// TODO: What do we do if this takes too long?
        log.Error("Failed to obtain certificate, DNS-Server took to long to start")
		return nil
	}
	return nil
}

// CleanUp is called after a challenge is finished, whether
// successful or not. It MUST free/remove any resources it
// allocated/created during Present. It SHOULD NOT require
// that Present ran successfully. It MUST return quickly.
func (d *DNSSolver) CleanUp(ctx context.Context, challenge acme.Challenge) error {
	err := d.DNS.ShutDown()
	if err != nil {
		fmt.Println("Error shutting down")
		fmt.Println(err)
	}
	return nil
}

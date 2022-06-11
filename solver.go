package tls

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/request"
	"github.com/mholt/acmez/acme"
	"github.com/miekg/dns"
)

type DNSSolver struct {
	Addr   string
	Config *dnsserver.Config
	DNS    *ACMEServer
}

type ACMEServer struct {
	m      sync.Mutex  // protects the servers
	server *dns.Server // 0 is a net.Listener, 1 is a net.PacketConn (a *UDPConn) in our case.
}

var (
	ch chan string
)

func NewACMEServer(addr string) *ACMEServer {
	as := &ACMEServer{}
	return as
}

const (
	tcp = 0
	udp = 1
)

type (
	// Key is the context key for the current server added to the context.
	Key struct{}

	// LoopKey is the context key to detect server wide loops.
	LoopKey struct{}
)

func (as *ACMEServer) ServePacket(p net.PacketConn, challenge acme.Challenge) error {
	fmt.Println("ACMEServer Starting to serve UDP!!!!!!!!!")
	as.m.Lock()
	as.server = &dns.Server{PacketConn: p, Net: "udp", Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		acme_request := true
		fmt.Println("ACMEHandler Handling DNS Challenge UDP!!!!")
		state := request.Request{W: w, Req: r}
		hdr := dns.RR_Header{Name: state.QName(), Rrtype: dns.TypeTXT, Class: dns.ClassANY, Ttl: 0}
		m := new(dns.Msg)
		m.SetReply(r)
		if state.QType() != dns.TypeTXT {
			fmt.Println("Received Wrong DNS Request")
			acme_request = false
		}

		if !(strings.HasPrefix(state.Name(), "_acme-challenge")) {
			fmt.Println("Received Something else!")
			acme_request = false
		}

		if acme_request {
			fmt.Println("Received ACME Challenge!")
			m.Answer = append(m.Answer, &dns.TXT{Hdr: hdr, Txt: []string{challenge.DNS01KeyAuthorization()}})
			fmt.Println(m)
			w.WriteMsg(m)
			fmt.Println("Done handling ACME Challenge UDP!!!!")
		} else {
			fmt.Println("Ignoring DNS request:", state.Name())
		}
	})}
	as.m.Unlock()

	return as.server.ActivateAndServe()
}

// Present is called just before a challenge is initiated.
// The implementation MUST prepare anything that is necessary
// for completing the challenge
// for CoreDNS that means that we need to start the DNS Server,
// serve exactly one request and
func (d DNSSolver) Present(ctx context.Context, challenge acme.Challenge) error {
	fmt.Println("Starting to solve the challenge!")
	var config []*dnsserver.Config
	config = append(config, d.Config)

	as := NewACMEServer(d.Addr)
	d.DNS = as

	addr := net.UDPAddr{
		Port: 1053,
		IP:   net.ParseIP("0.0.0.0"),
	}

	// l, err := net.Listen("tcp", d.Addr)
	l, err := net.ListenUDP("udp", &addr)
	if err != nil {
		fmt.Println("Failed to create Listener")
		fmt.Println(err)
	}

	go func() {
		err := as.ServePacket(l, challenge)
		if err != nil {
			fmt.Println("Received Error from ServePacket")
			fmt.Println(err)
		}
		fmt.Println("ACME DNS Server has been shutdown!")
	}()
	fmt.Println("DNS Server should be up")
	return nil
}

func (d DNSSolver) Wait(ctx context.Context, challenge acme.Challenge) error {
	fmt.Println("We Waitin")
	time.Sleep(10 * time.Second)
	return nil
}

// CleanUp is called after a challenge is finished, whether
// successful or not. It MUST free/remove any resources it
// allocated/created during Present. It SHOULD NOT require
// that Present ran successfully. It MUST return quickly.
func (d DNSSolver) CleanUp(ctx context.Context, challenge acme.Challenge) error {
	fmt.Println("Cleaning Up!")
	err := d.DNS.server.Shutdown()
	if err != nil {
		fmt.Println("Error shutting down")
		fmt.Println(err)
	}
	return nil
}

package tls

import (
	"context"
	"fmt"
	"strings"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
)


type ACMEHandler struct {
    Next plugin.Handler
}

const (
	dnsChallengeString   = "_acme-challenge."
	certificateAuthority = "letsencrypt.org"
    pluginName = "tlsplus"
)

func (h *ACMEHandler) Name() string { return pluginName }

func (h *ACMEHandler) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
    fmt.Println("Start of tlsplus ServeDNS")
	state := request.Request{W: w, Req: r}
	a := new(dns.Msg)
	a.SetReply(state.Req)
	a.Answer = []dns.RR{}
	//class := state.QClass()
	for _, question := range r.Question {
		zone := strings.ToLower(question.Name)
		if checkDNSChallenge(zone) {
			if question.Qtype == dns.TypeTXT {
                //a.Answer = append(a.Answer, &dns.TXT{Hdr: hdr, Txt: []string{challenge.DNS01KeyAuthorization()}})
                //w.WriteMsg(a)
			}
		}
	}

    fmt.Println("End of tlsplus ServeDNS")
	return h.Next.ServeDNS(ctx, w, r)
}

func checkDNSChallenge(zone string) bool {
	return strings.HasPrefix(zone, dnsChallengeString)
}

func (h *ACMEHandler) solveDNSChallenge(ctx context.Context, zone string, class uint16, a *dns.Msg) error {
	return nil
}

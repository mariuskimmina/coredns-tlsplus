package tls

import (
	"context"
	"strings"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/pkg/log"
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
	state := request.Request{W: w, Req: r}
	a := new(dns.Msg)
	a.SetReply(state.Req)
	a.Answer = []dns.RR{}
	class := state.QClass()
	for _, question := range r.Question {
		zone := strings.ToLower(question.Name)
		if checkDNSChallenge(zone) {
			if question.Qtype == dns.TypeTXT {
				err := h.solveDNSChallenge(ctx, zone, class, a)
				if err != nil {
					log.Errorf("acmeHandler.solveDNSChallenge for zone %s err: %+v", zone, err)
					return 0, err
				}
			}
		}
	}

	return h.Next.ServeDNS(ctx, w, r)
}

func checkDNSChallenge(zone string) bool {
	return strings.HasPrefix(zone, dnsChallengeString)
}

func (h *ACMEHandler) solveDNSChallenge(ctx context.Context, zone string, class uint16, a *dns.Msg) error {
	return nil
}

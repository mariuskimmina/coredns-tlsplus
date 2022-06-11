package tls

import (
	"github.com/caddyserver/certmagic"
	"github.com/coredns/coredns/core/dnsserver"
)

func NewCertmagicConfig(config *dnsserver.Config) *certmagic.Config {
	solver := DNSSolver{
		Addr:   "127.0.0.1:53",
		Config: config,
	}
	certmagic.DefaultACME.DNS01Solver = solver
	acmeConfig := certmagic.NewDefault()

	return acmeConfig
}

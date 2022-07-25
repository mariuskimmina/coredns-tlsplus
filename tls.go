package tls

import (
	"crypto/tls"
	"github.com/coredns/coredns/core/dnsserver"
)

func configureTLS(conf *dnsserver.Config, tlsconf *tls.Config, clientAuth tls.ClientAuthType) {
	tlsconf.ClientAuth = clientAuth
	// NewTLSConfigs only sets RootCAs, so we need to let ClientCAs refer to it.
	tlsconf.ClientCAs = tlsconf.RootCAs
	conf.TLSConfig = tlsconf
}

package tls

import (
	"github.com/caddyserver/certmagic"
)

func NewCertmagicConfig() *certmagic.Config {
	acmeConfig := certmagic.NewDefault()
    acmeConfig.TLSConfig().InsecureSkipVerify = true
	return acmeConfig
}

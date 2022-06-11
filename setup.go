package tls

import (
	"context"
	ctls "crypto/tls"
	"fmt"

	"github.com/caddyserver/certmagic"
	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/pkg/tls"
)

func init() { plugin.Register("tls", setup) }

func setup(c *caddy.Controller) error {
	err := parseTLS(c)
	if err != nil {
		return plugin.Error("tls", err)
	}
	return nil
}

type ACMEManager struct {
    Config *certmagic.Config
    Issuer *certmagic.ACMEIssuer
    Zone string
}

func NewACMEManager(config *dnsserver.Config, zone string) *ACMEManager {
    fmt.Println("Start of NewACMEManager")
    acmeIssuerTemplate := certmagic.ACMEIssuer{
        Agreed:                  true,
        DisableHTTPChallenge:    true,
        DisableTLSALPNChallenge: true,
    }
    acmeIssuerTemplate.TestCA = "https://localhost:14000/dir" //pebble
    acmeIssuerTemplate.CA = "https://localhost:14000/dir"
    acmeConfigTemplate := NewCertmagicConfig(config)
    cache := certmagic.NewCache(certmagic.CacheOptions{
        GetConfigForCert: func(cert certmagic.Certificate) (*certmagic.Config, error) {
            return acmeConfigTemplate, nil
        },
    })
    acmeConfig := certmagic.New(cache, *acmeConfigTemplate)
    acmeIssuer := certmagic.NewACMEIssuer(acmeConfig, acmeIssuerTemplate)

    fmt.Println("End of NewACMEManager")
    return &ACMEManager{
        Config: acmeConfig,
        Issuer: acmeIssuer,
        Zone: zone,
    }


}

func parseTLS(c *caddy.Controller) error {
	fmt.Println("Start of parseTLS")
	config := dnsserver.GetConfig(c)
	var tlsconf *ctls.Config
	var err error
	clientAuth := ctls.NoClientCert

	if config.TLSConfig != nil {
		return plugin.Error("tls", c.Errf("TLS already configured for this server instance"))
	}
	i := 1
	for c.Next() {
		fmt.Printf("Run number: %d \n", i)
		i++
		args := c.RemainingArgs()
		fmt.Printf("remaining args: %s \n", args)

		if args[0] == "acme" {
			// start of the acme flow,
			// first check if a certificate is already present
			fmt.Println("Starting ACME")




            ctx := context.Background()

			var domainNameACME string
			for c.NextBlock() {
				fmt.Println("ACME Config Block Found")
				token := c.Val()
				switch token {
				case "domain":
					fmt.Println("Found Keyword Domain")
					domainArgs := c.RemainingArgs()
					if len(domainArgs) > 1 {
						return plugin.Error("tls", c.Errf("To many arguments to domain"))
					}
					domainNameACME = domainArgs[0]
					fmt.Println(domainNameACME)
				default:
					return c.Errf("unknown argument to acme '%s'", token)
				}
			}

            manager := NewACMEManager(config, domainNameACME)
            err := manager.Config.ObtainCertSync(ctx, manager.Zone)
            if err != nil {
                return c.Errf("failed to Obtain Cert '%v'", err)
            }


			fmt.Println("End of ACME config parsing")
		} else {
			fmt.Println("Uing manually conigured certificate")
			if len(args) < 2 || len(args) > 3 {
				return plugin.Error("tls", c.ArgErr())
			}
			for c.NextBlock() {
				switch c.Val() {
				case "client_auth":
					authTypeArgs := c.RemainingArgs()
					if len(authTypeArgs) != 1 {
						return c.ArgErr()
					}
					switch authTypeArgs[0] {
					case "nocert":
						clientAuth = ctls.NoClientCert
					case "request":
						clientAuth = ctls.RequestClientCert
					case "require":
						clientAuth = ctls.RequireAnyClientCert
					case "verify_if_given":
						clientAuth = ctls.VerifyClientCertIfGiven
					case "require_and_verify":
						clientAuth = ctls.RequireAndVerifyClientCert
					default:
						return c.Errf("unknown authentication type '%s'", authTypeArgs[0])
					}
				default:
					return c.Errf("unknown option '%s'", c.Val())
				}
			}
			tlsconf, err = tls.NewTLSConfigFromArgs(args...)
			if err != nil {
				return err
			}
			configureTLS(config, tlsconf, clientAuth)
		}
	}
	return nil
}

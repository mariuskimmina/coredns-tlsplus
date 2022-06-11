package tls

import (
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



            acmeTemplate := certmagic.ACMEIssuer{
                Agreed: true,
                DisableHTTPChallenge: true,
                DisableTLSALPNChallenge: true,
            }

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

            acmeTemplate.TestCA = "https://localhost:14000/dir" //pebble

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

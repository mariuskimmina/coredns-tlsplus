package tls

import (
	"context"
	"strconv"
	"sync"
	"time"

	ctls "crypto/tls"
	"fmt"

	"github.com/caddyserver/certmagic"
	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"

	//"github.com/coredns/coredns/plugin/pkg/log"
	clog "github.com/coredns/coredns/plugin/pkg/log"
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

var (
	log            = clog.NewWithPlugin("tls")
	r              = renewCert{quit: make(chan bool), renew: make(chan bool)}
	once, shutOnce sync.Once
)

const (
	argDomain   = "domain"
	argCa       = "ca"
	argCaCert   = "cacert"
	argCertPath = "certpath"
	argPort     = "port"
)

func parseTLS(c *caddy.Controller) error {
	config := dnsserver.GetConfig(c)

	var tlsconf *ctls.Config
	var cert *certmagic.Certificate
	var err error
	clientAuth := ctls.NoClientCert

	if config.TLSConfig != nil {
		return plugin.Error("tls", c.Errf("TLS already configured for this server instance"))
	}
	i := 1
	for c.Next() {
		i++
		args := c.RemainingArgs()

		if args[0] == "acme" {
			log.Info("Starting ACME Setup")
			// start of the acme flow,

			//check if cert is present and valid
			ctx := context.Background()

			var domainNameACME string
			var ca string
			var caCert string
            var port string
			//certPath := "/home/marius/.local/share/certmagic/certificates/example.com/example.com.crt"

			for c.NextBlock() {
				token := c.Val()
				switch token {
				case argDomain:
					domainArgs := c.RemainingArgs()
					if len(domainArgs) > 1 {
						return plugin.Error("tls", c.Errf("To many arguments to domain"))
					}
					domainNameACME = domainArgs[0]
				case argCa:
					caArgs := c.RemainingArgs()
					if len(caArgs) > 1 {
						return plugin.Error("tls", c.Errf("To many arguments to ca"))
					}
					ca = caArgs[0]
				case argCaCert:
					caCertArgs := c.RemainingArgs()
					if len(caCertArgs) > 1 {
						return plugin.Error("tls", c.Errf("To many arguments to cacert"))
					}
					caCert = caCertArgs[0]
				case argPort:
					portArgs := c.RemainingArgs()
					if len(portArgs) > 1 {
						return plugin.Error("tls", c.Errf("To many arguments to port"))
					}
					port = portArgs[0]
				case argCertPath:
					certPathArgs := c.RemainingArgs()
					if len(certPathArgs) > 1 {
						return plugin.Error("tls", c.Errf("To many arguments to CertPath"))
					}
					//certPath = certPathArgs[0]
				default:
					return c.Errf("unknown argument to acme '%s'", token)
				}
			}

            portNumber := 53
            if port != "" {
                portNumber, err = strconv.Atoi(port)
                if err != nil {
                    log.Errorf("Failed to convert port argument to integer: %v \n", err)
                }
            }

			manager := NewACMEManager(config, domainNameACME, ca, caCert, portNumber)

			var names []string
			names = append(names, manager.Zone)

			tlsconf, cert, err = manager.configureTLSwithACME(ctx)
			config.TLSConfig = tlsconf

			once.Do(func() {
				// start a loop that checks for renewals
				go func() {
					log.Debug("Starting certificate renewal loop in the background")
					for {
						time.Sleep(40 * time.Second)
						if cert.NeedsRenewal(manager.Config) {
							log.Info("Certificate expiring soon, initializing reload")
							r.renew <- true
						}
					}
				}()
				caddy.RegisterEventHook("updateCert", hook)
			})
			shutOnce.Do(func() {
				c.OnFinalShutdown(func() error {
					log.Info("Quiting renewal checker")
					r.quit <- true
					return nil
				})
			})
		} else {
			//No ACME part - plugin continues to work like the normal tls plugin
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

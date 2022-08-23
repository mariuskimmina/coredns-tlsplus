package tls

import (
	"context"
	"os"
	"strconv"
	"sync"
	"time"

	ctls "crypto/tls"

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
	argDomain        = "domain"
	argCheckInternal = "checkinterval"
	argCa            = "ca"
	argCaCert        = "cacert"
	argEmail         = "email"
	argCertPath      = "certpath"
	argPort          = "port"
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
			log.Debug("Starting ACME Setup")

			ctx := context.Background()

			var domainNameACME string
			var ca string
			var caCert string
			var port string
			var email string
			checkInterval := 15
			userHome, homeExists := os.LookupEnv("HOME")
			if !homeExists {
				log.Error("Environment Variable $HOME needs to be set.")
			}
			certPath := userHome + "/.local/share/certmagic/"

			for c.NextBlock() {
				token := c.Val()
				switch token {
				case argDomain:
					domainArgs := c.RemainingArgs()
					if len(domainArgs) > 1 {
						return plugin.Error("tls", c.Errf("Too many arguments to domain"))
					}
					domainNameACME = domainArgs[0]
				case argCa:
					caArgs := c.RemainingArgs()
					if len(caArgs) > 1 {
						return plugin.Error("tls", c.Errf("Too many arguments to ca"))
					}
					ca = caArgs[0]
				case argCaCert:
					caCertArgs := c.RemainingArgs()
					if len(caCertArgs) > 1 {
						return plugin.Error("tls", c.Errf("Too many arguments to cacert"))
					}
					caCert = caCertArgs[0]
				case argEmail:
					emailArgs := c.RemainingArgs()
					if len(emailArgs) > 1 {
						return plugin.Error("tls", c.Errf("Too many arguments to email"))
					}
					email = emailArgs[0]
				case argPort:
					portArgs := c.RemainingArgs()
					if len(portArgs) > 1 {
						return plugin.Error("tls", c.Errf("Too many arguments to port"))
					}
					port = portArgs[0]
				case argCertPath:
					certPathArgs := c.RemainingArgs()
					if len(certPathArgs) > 1 {
						return plugin.Error("tls", c.Errf("Too many arguments to CertPath"))
					}
					certPath = certPathArgs[0]
				case argCheckInternal:
					checkIntervalArgs := c.RemainingArgs()
					if len(checkIntervalArgs) > 1 {
						return plugin.Error("tls", c.Errf("Too many arguments to checkInterval"))
					}
					interval, err := strconv.Atoi(checkIntervalArgs[0])
					if err != nil {
						return plugin.Error("Failed to convert checkInterval argument to integer: %v \n", err)
					}
					checkInterval = interval
				default:
					return c.Errf("unknown argument to acme '%s'", token)
				}
			}

			// the ACME DNS-01 Challenge doesn't work with other ports than 53
			// this option is really only there to use in tests with Pebble
			portNumber := 53
			if port != "" {
				portNumber, err = strconv.Atoi(port)
				if err != nil {
					log.Errorf("Failed to convert port argument to integer: %v \n", err)
				}
			}

			manager := NewACMEManager(config, domainNameACME, ca, certPath, caCert, portNumber, email)

			var names []string
			names = append(names, manager.Zone)

			tlsconf, cert, err = manager.configureTLSwithACME(ctx)
			if err != nil {
				log.Errorf("Failed to setup TLS automatically: %v \n", err)
			}
			config.TLSConfig = tlsconf

			once.Do(func() {
				// start a loop that checks for renewals
				go func() {
					log.Debug("Starting certificate renewal loop in the background")
					for {
						time.Sleep(time.Duration(checkInterval) * time.Minute)
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
					log.Debug("Quiting renewal checker")
					r.quit <- true
					return nil
				})
			})
		} else {
			//No ACME part - plugin continues to work like the normal tls plugin
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

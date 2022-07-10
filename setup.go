package tls

import (
	"context"
	"crypto/ecdsa"
	"sync"
	"time"

	ctls "crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/caddyserver/certmagic"
	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"

	//"github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/plugin/pkg/tls"
)

func init() { plugin.Register("tls", setup) }

func setup(c *caddy.Controller) error {
	err := parseTLS(c)
    config := dnsserver.GetConfig(c)
	if err != nil {
		return plugin.Error("tls", err)
	}
    acmeHandler := &ACMEHandler{}

    config.AddPlugin(func(next plugin.Handler) plugin.Handler {
        acmeHandler.Next = next
        return acmeHandler
    }) 
	return nil
}

var (
    r              = renewCert{quit: make(chan bool), renew: make(chan bool)}
	once, shutOnce sync.Once
)

const (
    argDomain = "domain"
    argCa = "ca"
    argCertPath = "certpath"
)


func parseTLS(c *caddy.Controller) error {
	fmt.Println("Start of parseTLS")
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
			// start of the acme flow,

            //check if cert is present and valid 


			ctx := context.Background()

			var domainNameACME string
            var ca string
            //certPath := "/home/marius/.local/share/certmagic/certificates/example.com/example.com.crt"

			for c.NextBlock() {
				fmt.Println("ACME Config Block Found")
				token := c.Val()
				switch token {
				case argDomain:
					fmt.Println("Found Keyword Domain")
					domainArgs := c.RemainingArgs()
					if len(domainArgs) > 1 {
						return plugin.Error("tls", c.Errf("To many arguments to domain"))
					}
					domainNameACME = domainArgs[0]
				case argCa:
					fmt.Println("Found Keyword CA")
					caArgs := c.RemainingArgs()
					if len(caArgs) > 1 {
						return plugin.Error("tls", c.Errf("To many arguments to ca"))
					}
					ca = caArgs[0]
				case argCertPath:
					fmt.Println("Found Keyword CertPath")
					certPathArgs := c.RemainingArgs()
					if len(certPathArgs) > 1 {
						return plugin.Error("tls", c.Errf("To many arguments to CertPath"))
					}
					//certPath = certPathArgs[0]
				default:
					return c.Errf("unknown argument to acme '%s'", token)
				}
			}
			fmt.Println("Starting ACME")

			manager := NewACMEManager(config, domainNameACME, ca)

            var names []string
            names = append(names, manager.Zone)
            //err = manager.ManageCert(ctx, names)
            //if err != nil {
                //log.Errorf("Error in ManageCert '%v'", err)
            //}

			// start using the obtained certificate
            //keyFile := "/home/marius/.local/share/certmagic/certificates/example.com/example.com.key"
            //var certBytes []byte
            //var keyBytes []byte

            //counter := 0
            //for {
                //fmt.Println("Waiting for Certificate")
                //if counter >= 5 {
                    //break
                //}

                // obtaining a certificate happens asynchronous
                // if the certfile is present we are good to go 
                // if not we wait
                //_, err = os.ReadFile(certPath)
                //if err != nil {
                    //counter = counter + 1
                    //time.Sleep(1 * time.Second)
                    //continue
                //}
                //fmt.Println("Done waiting for certificate")
                //break
            //}

            tlsconf, cert, err = manager.configureTLSwithACME(ctx)
            config.TLSConfig = tlsconf

            // a CoreDNSSolver doesn't actually do anything because CoreDNS is 
            // already up and running and has a handler to solve the ACME Challenge,
            // there is nothing left for the solver to do, but we still need to
            // set it. If we don't set it the other solver would stil try to start
            // a dns.Server.
            solverCoreDNS := &CoreDNSSolver{}
            manager.Issuer.DNS01Solver = solverCoreDNS

            // start a loop that checks for renewals
            //r.renew <- false
            go func() {
                fmt.Println("Starting renewal checker loop")
                for {
                    time.Sleep(40 * time.Second)
                    fmt.Println("checking renewal")
                    if cert.NeedsRenewal(manager.Config) {
                        fmt.Println("initialize renewal")
                        r.renew <- true
                        break
                    } else {
                        fmt.Println("no renewal needed")
                    }
                }
            }()

            // this part is taken from to the reload plugin
            // basically we need to restart/reload CoreDNS whenever
            // a certificate has been renewed
            fmt.Println("Registering Hook")
            once.Do(func() {
                caddy.RegisterEventHook("updateCert", hook)
            })
            shutOnce.Do(func() {
                c.OnFinalShutdown(func() error {
                    r.quit <- true
                    return nil
                })
            })


			fmt.Println("End of ACME config parsing")
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

// encodePrivateKey encodes an ECDSA private key to PEM format.
func encodePrivateKey(key *ecdsa.PrivateKey) ([]byte, error) {
	derKey, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}

	keyBlock := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: derKey,
	}

	return pem.EncodeToMemory(keyBlock), nil
}

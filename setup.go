package tls

import (
	"context"
	"crypto/ecdsa"
	"strconv"
	"time"

	//"crypto/elliptic"
	//"crypto/rand"
	ctls "crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/caddyserver/certmagic"
	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/pkg/log"
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

type ACMEManager struct {
	Config *certmagic.Config     //Configs for Serving
	Issuer *certmagic.ACMEIssuer //The ACME Client
	Zone   string                //The Domain
}

// NewACMEManager create a new ACMEManager
func NewACMEManager(config *dnsserver.Config, zone string, ca string) *ACMEManager {
	fmt.Println("Start of NewACMEManager")

    if ca == "" {
        ca = "localhost:14000/dir" //pebble default
    }

	// TODO: this lets our  acme client trust the pebble cert
	// this is only needed for testing and should not be in production
	// figure out how to only do this in test cases
	certbytes, err := os.ReadFile("test/certs/pebble.minica.pem")
	if err != nil {
		fmt.Println(err.Error())
		panic("Failed to load Cert")
	}
	pemcert, _ := pem.Decode(certbytes)
	if pemcert == nil {
		fmt.Println("pemcert not found")
	}
	cert, err := x509.ParseCertificate(pemcert.Bytes)
	if err != nil {
		fmt.Println(err)
		panic("Failed to parse Cert")
	}
	pool, err := x509.SystemCertPool()
	if err != nil {
		fmt.Println(err)
		panic("Failed to get system Certpool")
	}
	pool.AddCert(cert)

    portNumber, err := strconv.Atoi(config.Port)
	if err != nil {
		fmt.Println(err)
		panic("Failed to convert config.Port to integer")
	}

	//TODO: the address cannot be hardcoded
	solver := &DNSSolver{
        Port: portNumber,
		Addr: "127.0.0.1:1053",
	}


	acmeIssuerTemplate := certmagic.ACMEIssuer{
		Agreed:                  true,
		DisableHTTPChallenge:    true,
		DisableTLSALPNChallenge: true,
		CA:                      ca,
		TestCA:                  ca,
		Email:                   "test@test.test",
		DNS01Solver:             solver,
		TrustedRoots:            pool,
	}

	acmeConfigTemplate := NewCertmagicConfig()
	cache := certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(cert certmagic.Certificate) (*certmagic.Config, error) {
			return acmeConfigTemplate, nil
		},
	})
	acmeConfig := certmagic.New(cache, *acmeConfigTemplate)
	acmeIssuer := certmagic.NewACMEIssuer(acmeConfig, acmeIssuerTemplate)
	acmeConfig.Issuers = append(acmeConfig.Issuers, acmeIssuer)

	fmt.Println("End of NewACMEManager")
	return &ACMEManager{
		Config: acmeConfig,
		Issuer: acmeIssuer,
		Zone:   zone,
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
			fmt.Println("Starting ACME")

			ctx := context.Background()

			var domainNameACME string
            var ca string
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
				case "ca":
					fmt.Println("Found Keyword CA")
					caArgs := c.RemainingArgs()
					if len(caArgs) > 1 {
						return plugin.Error("tls", c.Errf("To many arguments to ca"))
					}
					ca = caArgs[0]
				default:
					return c.Errf("unknown argument to acme '%s'", token)
				}
			}

			manager := NewACMEManager(config, domainNameACME, ca)

            var names []string
            names = append(names, manager.Zone)
            manager.Config.RenewalWindowRatio = 0.9
            err := manager.Config.ManageAsync(ctx, names)
            if err != nil {
                log.Errorf("Error in ManageAsync '%v'", err)
            }

			// start using the obtained certificate
            certFile := "/home/marius/.local/share/certmagic/certificates/example.com/example.com.crt"
            keyFile := "/home/marius/.local/share/certmagic/certificates/example.com/example.com.key"
            var certBytes []byte
            var keyBytes []byte

            for {
                // obtaining a certificate happens asynchronous
                // if the certfile is present we are good to go 
                // if not we wait
                _, err = os.ReadFile(certFile)
                if err != nil {
                    time.Sleep(1 * time.Second)
                    continue
                }
                break
            }
			fmt.Println("Starting to configure Certificate")
			certBytes, err = os.ReadFile(certFile)
			if err != nil {
				return c.Errf("failed to Read Cert '%v'", err)
			}
			keyBytes, err = os.ReadFile(keyFile)
			if err != nil {
				return c.Errf("failed to Read Key '%v'", err)
			}

			cert, err := ctls.X509KeyPair(certBytes, keyBytes)
			if err != nil {
				return c.Errf("failed to Load Key Pair'%v'", err)
			}
			tlsconf := &ctls.Config{
				Certificates: []ctls.Certificate{cert},
			}
			//var newArgs []string
			//newArgs = append(newArgs, cert)
			//newArgs = append(newArgs, key)

			//tlsconf, err = tls.NewTLSConfigFromArgs(newArgs...)
			//if err != nil {
			//return err
			//}
			//fmt.Println("Starting to set TLSConf")
			//configureTLS(config, tlsconf, clientAuth)
			//tlsconf.ClientAuth = clientAuth
			// NewTLSConfigs only sets RootCAs, so we need to let ClientCAs refer to it.
			//tlsconf.ClientCAs = tlsconf.RootCAs
			config.TLSConfig = tlsconf

            // TODO: change DNSSolver config so that the 
            // acutal CoreDNS Server is used for further ACME Challenges
            solverCoreDNS := &CoreDNSSolver{}
            manager.Issuer.DNS01Solver = solverCoreDNS

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

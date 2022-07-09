package tls

import (
	"context"
	"strconv"
	"time"

	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/caddyserver/certmagic"
	"github.com/coredns/coredns/core/dnsserver"
)

type ACMEManager struct {
	Config *certmagic.Config     //Configs for Serving
	Issuer *certmagic.ACMEIssuer //The ACME Client
	Zone   string                //The Domain
}

// NewACMEManager create a new ACMEManager
func NewACMEManager(config *dnsserver.Config, zone string, ca string) *ACMEManager {
	fmt.Println("Start of NewACMEManager")

    if ca == "" {
        ca = "localhost:14001/dir" //pebble default
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

    certmagic.DefaultACME.Email = "test@test.test"

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
    acmeConfigTemplate.RenewalWindowRatio = 0.5
	cache := certmagic.NewCache(certmagic.CacheOptions{
        RenewCheckInterval: 5 * time.Second,
		GetConfigForCert: func(cert certmagic.Certificate) (*certmagic.Config, error) {
			return acmeConfigTemplate, nil
		},
	})
	acmeConfig := certmagic.New(cache, *acmeConfigTemplate)
	acmeIssuer := certmagic.NewACMEIssuer(acmeConfig, acmeIssuerTemplate)
	acmeConfig.Issuers = append(acmeConfig.Issuers, acmeIssuer)
    certmagic.RateLimitEvents = 100

	fmt.Println("End of NewACMEManager")
	return &ACMEManager{
		Config: acmeConfig,
		Issuer: acmeIssuer,
		Zone:   zone,
	}
}

func (a *ACMEManager) GetCert(zone string) error {
	err := a.Config.ObtainCertSync(context.Background(), zone)
	return err
}

func (a *ACMEManager) ManageCert(ctx context.Context, zone []string) error {
	fmt.Println("Start of ManageCert")
	err := a.Config.ManageSync(ctx, zone)
	fmt.Println("End of ManageCert")
	return err
}

func (a *ACMEManager) RenewCert(ctx context.Context, zone string) error {
	err := a.Config.RenewCertSync(ctx, zone, false)
	return err
}

func (a *ACMEManager) CacheCertificate(ctx context.Context, zone string) (certmagic.Certificate, error) {
	cert, err := a.Config.CacheManagedCertificate(ctx, zone)
	return cert, err
}

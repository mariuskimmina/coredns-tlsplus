package tls

import (
	"context"
	"errors"
	"io/fs"

	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/caddyserver/certmagic"
)

type CertManager struct {
	Config *certmagic.Config
	Issuer *certmagic.ACMEIssuer
	Zone   string
}

func NewConfig(path string) *certmagic.Config {
	acmeConfigTemplate := certmagic.NewDefault()
	acmeConfigTemplate.RenewalWindowRatio = 0.7
	acmeConfigTemplate.Storage = &certmagic.FileStorage{
		Path: path,
	}
	cache := certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(cert certmagic.Certificate) (*certmagic.Config, error) {
			return acmeConfigTemplate, nil
		},
	})
	acmeConfig := certmagic.New(cache, *acmeConfigTemplate)
	return acmeConfig
}

func newDNSSolver(port int) *DNSSolver {
	readyChan := make(chan string)
	solver := &DNSSolver{
		Port:      port,
		readyChan: readyChan,
	}
	return solver
}

func NewIssuer(config *certmagic.Config, ca string, email string, pool *x509.CertPool, solver *DNSSolver) *certmagic.ACMEIssuer {
	certmagic.DefaultACME.Email = "test@test.com"
	acmeIssuerTemplate := certmagic.ACMEIssuer{
		Agreed:                  true,
		DisableHTTPChallenge:    true,
		DisableTLSALPNChallenge: true,
		CA:                      ca,
		TestCA:                  ca,
		Email:                   email,
		DNS01Solver:             solver,
		TrustedRoots:            pool,
	}

	acmeIssuer := certmagic.NewACMEIssuer(config, acmeIssuerTemplate)
	config.Issuers = append(config.Issuers, acmeIssuer)

	return acmeIssuer
}

func setupCertPool(caCert string) (*x509.CertPool, error) {
	pool, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}

	if caCert != "" {
		certbytes, err := os.ReadFile(caCert)
		if err != nil {
			return nil, err
		}
		pemcert, _ := pem.Decode(certbytes)
		if pemcert == nil {
			return nil, err
		}
		cert, err := x509.ParseCertificate(pemcert.Bytes)
		if err != nil {
			return nil, err
		}
		pool.AddCert(cert)
	}
	return pool, nil
}

// NewACMEManager create a new ACMEManager
func NewCertManager(zone string, config *certmagic.Config, issuer *certmagic.ACMEIssuer) *CertManager {
	return &CertManager{
		Config: config,
		Issuer: issuer,
		Zone:   zone,
	}
}

func (c *CertManager) configureTLSwithACME(ctx context.Context) (*tls.Config, *certmagic.Certificate, error) {
	var cert certmagic.Certificate
	var err error

	// try loading existing certificate
	cert, err = c.Config.CacheManagedCertificate(ctx, c.Zone)
	if err != nil {
		log.Info("Obtaining TLS Certificate, may take a moment")
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, nil, err
		}
		err = c.GetCert(c.Zone)
		if err != nil {
			return nil, nil, err
		}
		cert, err = c.CacheCertificate(ctx, c.Zone)
		if err != nil {
			return nil, nil, err
		}
	}

	// check if renewal is required
	if cert.NeedsRenewal(c.Config) {
		log.Info("Renewing TLS Certificate")
		var err error
		err = c.RenewCert(ctx, c.Zone)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: renewing certificate: %w", c.Zone, err)
		}
		// successful renewal, so update in-memory cache
		cert, err = c.CacheCertificate(ctx, c.Zone)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: reloading renewed certificate into memory: %v", c.Zone, err)
		}
	}

	// check again, if it still needs renewal something went wrong
	if cert.NeedsRenewal(c.Config) {
		log.Error("Failed to renew certificate")
	}

	//tlsConfig := acmeManager.Config.TLSConfig()
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert.Certificate}}
	tlsConfig.ClientAuth = tls.NoClientCert
	tlsConfig.ClientCAs = tlsConfig.RootCAs

	return tlsConfig, &cert, nil
}

func (c *CertManager) GetCert(zone string) error {
	err := c.Config.ObtainCertSync(context.Background(), zone)
	return err
}

func (c *CertManager) RenewCert(ctx context.Context, zone string) error {
	err := c.Config.RenewCertSync(ctx, zone, false)
	return err
}

func (c *CertManager) CacheCertificate(ctx context.Context, zone string) (certmagic.Certificate, error) {
	cert, err := c.Config.CacheManagedCertificate(ctx, zone)
	return cert, err
}

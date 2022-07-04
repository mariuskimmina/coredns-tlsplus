package tls

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io/fs"

	"github.com/coredns/coredns/core/dnsserver"
)

func configureTLS(conf *dnsserver.Config, tlsconf *tls.Config, clientAuth tls.ClientAuthType) {
	tlsconf.ClientAuth = clientAuth
	// NewTLSConfigs only sets RootCAs, so we need to let ClientCAs refer to it.
	tlsconf.ClientCAs = tlsconf.RootCAs
	conf.TLSConfig = tlsconf
}

func configureTLSwithACME(ctx context.Context, acmeManager *ACMEManager) (*tls.Config, error) {
    fmt.Println("Start of configureTLSwithACME")

    // try loading existing certificate
	cert, err := acmeManager.Config.CacheManagedCertificate(ctx, acmeManager.Zone)
	if err != nil {
        fmt.Println("OBTAIN")
        if !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
        acmeManager.GetCert(acmeManager.Zone)
        if err != nil {
            return nil, err
        }
        cert, err = acmeManager.Config.CacheManagedCertificate(ctx, acmeManager.Zone)
        if err != nil {
            return nil, err
        }
	}

    // check if renewal is required
    if cert.NeedsRenewal(acmeManager.Config) {
        fmt.Println("RENEWAL")
        var err error
        err = acmeManager.Config.RenewCertSync(ctx, acmeManager.Zone, false)
        if err != nil {
            return nil, fmt.Errorf("%s: renewing certificate: %w", acmeManager.Zone, err)
        }
        // successful renewal, so update in-memory cache
        cert, err = acmeManager.Config.CacheManagedCertificate(ctx, acmeManager.Zone)
        if err != nil {
            return nil, fmt.Errorf("%s: reloading renewed certificate into memory: %v", acmeManager.Zone, err)
        }
    }



    //tlsConfig := acmeManager.Config.TLSConfig()
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert.Certificate}}
	tlsConfig.ClientAuth = tls.NoClientCert
	tlsConfig.ClientCAs = tlsConfig.RootCAs

    fmt.Println("End of configureTLSwithACME")
    return tlsConfig, nil
}

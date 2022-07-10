package tls

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io/fs"

	"github.com/caddyserver/certmagic"
	"github.com/coredns/coredns/core/dnsserver"
)

func configureTLS(conf *dnsserver.Config, tlsconf *tls.Config, clientAuth tls.ClientAuthType) {
	tlsconf.ClientAuth = clientAuth
	// NewTLSConfigs only sets RootCAs, so we need to let ClientCAs refer to it.
	tlsconf.ClientCAs = tlsconf.RootCAs
	conf.TLSConfig = tlsconf
}

func configureTLSwithACME(ctx context.Context, acmeManager *ACMEManager) (*tls.Config, *certmagic.Certificate, error) {
    fmt.Println("Start of configureTLSwithACME")

    var cert certmagic.Certificate
    var err error

    // try loading existing certificate
	cert, err = acmeManager.Config.CacheManagedCertificate(ctx, acmeManager.Zone)
	if err != nil {
        fmt.Println("obtaining a cert")
        if !errors.Is(err, fs.ErrNotExist) {
            fmt.Println(err)
			return nil, nil, err
		}
        acmeManager.GetCert(acmeManager.Zone)
        if err != nil {
            fmt.Println(err)
            return nil, nil, err
        }
        cert, err = acmeManager.CacheCertificate(ctx, acmeManager.Zone)
        if err != nil {
            fmt.Println(err)
            return nil, nil, err
        }
	}

    fmt.Println("Loaded a certificate, lets see if it needs renewal")
    // check if renewal is required
    if cert.NeedsRenewal(acmeManager.Config) {
        fmt.Println("renewing a cert")
        var err error
        err = acmeManager.RenewCert(ctx, acmeManager.Zone)
        if err != nil {
            return nil, nil, fmt.Errorf("%s: renewing certificate: %w", acmeManager.Zone, err)
        }
        // successful renewal, so update in-memory cache
        cert, err = acmeManager.CacheCertificate(ctx, acmeManager.Zone)
        if err != nil {
            return nil, nil, fmt.Errorf("%s: reloading renewed certificate into memory: %v", acmeManager.Zone, err)
        }
    } else {
        fmt.Println("No Renewal needed, keep going")
    }

    if cert.NeedsRenewal(acmeManager.Config) {
        fmt.Println("RENEWAL failed!!!")
    } else {
        fmt.Println("Certificate is ready")
    }



    //tlsConfig := acmeManager.Config.TLSConfig()
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert.Certificate}}
	tlsConfig.ClientAuth = tls.NoClientCert
	tlsConfig.ClientCAs = tlsConfig.RootCAs

    fmt.Println("End of configureTLSwithACME")
    return tlsConfig, &cert, nil
}

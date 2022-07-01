package tls

import (
	"context"
	"fmt"

	"github.com/mholt/acmez/acme"
)

type CoreDNSSolver struct {
}


// Present is called just before a challenge is initiated.
// The implementation MUST prepare anything that is necessary
// for completing the challenge
// for CoreDNS that means that we need to start the DNS Server,
// serve exactly one request and
func (d *CoreDNSSolver) Present(ctx context.Context, challenge acme.Challenge) error {
	fmt.Println("Start of CoreDNSSover Present !")
	fmt.Println("End of CoreDNSSover Present !")
	return nil
}

func (d *CoreDNSSolver) Wait(ctx context.Context, challenge acme.Challenge) error {
	fmt.Println("Start of CoreDNSSolver Wait")
	fmt.Println("End of CoreDNSSolver Wait")
	return nil
}

// CleanUp is called after a challenge is finished, whether
// successful or not. It MUST free/remove any resources it
// allocated/created during Present. It SHOULD NOT require
// that Present ran successfully. It MUST return quickly.
func (d *CoreDNSSolver) CleanUp(ctx context.Context, challenge acme.Challenge) error {
	fmt.Println("Start of CoreDNSSolver CleanUp!")
	fmt.Println("End of CoreDNSSolver CleanUp!")
	return nil
}

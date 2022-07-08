package tls

import (
	"context"
	"fmt"

	"github.com/mholt/acmez/acme"
)

// a CoreDNSSolver doesn't actually do anything (other than 
// fullfilling the acmez.Solver interface) because CoreDNS is 
// already up and running and has a handler to solve the ACME Challenge,
// there is nothing left for the solver to do, but we still need to
// set it. If we don't set it the other solver would stil try to start
// a dns.Server.
type CoreDNSSolver struct {
}

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

func (d *CoreDNSSolver) CleanUp(ctx context.Context, challenge acme.Challenge) error {
	fmt.Println("Start of CoreDNSSolver CleanUp!")
	fmt.Println("End of CoreDNSSolver CleanUp!")
	return nil
}

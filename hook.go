package tls

import (
	"fmt"
	"time"

	"github.com/coredns/caddy"
)

func hook(event caddy.EventName, info interface{}) error {
	if event != caddy.InstanceStartupEvent {
		return nil
	}

	// this should be an instance. ok to panic if not
	instance := info.(*caddy.Instance)
	

	go func() {
        tick := time.NewTicker(20 * time.Second)

		for {
			select {
			case <-tick.C:
                fmt.Println("RELOADING!!!!")
                corefile, err := caddy.LoadCaddyfile(instance.Caddyfile().ServerType())
				if err != nil {
					continue
				}
                instance.Restart(corefile)
			}
		}
	}()
	return nil
}

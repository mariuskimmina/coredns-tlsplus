# tlsplus

## Name

*tlsplus* - generate and manage TLS certificates for you.

## Description

*tlsplus* is an alternative to the existing TLS plugin for CoreDNS, it can be used as a drop in replacement for the exisiting plugin and everything will continue to work.
What this plugin offers over the current builtin TLS plugin is the ability to generate and manage TLS certificates for you, so that you never have to worry about aquiring or renewing certificates,
all that will automatically be done for you.

CoreDNS supports queries that are encrypted using [TLS](https://datatracker.ietf.org/doc/html/rfc7858) or [HTTPS](https://datatracker.ietf.org/doc/html/rfc8484)
or are using gRPC (https://grpc.io/, not an IETF standard). Normally DNS traffic isn't encrypted at all (DNSSEC only signs resource records).
The *tlsplus* plugin allows you to either have CoreDNS generate and manage certificates for itself or configure the cryptographic keys yourself that are needed for all three
DNS-over-TLS, DNS-over-HTTPS or DNS-over-gRPC.

## Demo

The follwing show's a CoreDNS Server starting with the tlsplus plugin, obtaining a cerificate and serving DNS over TLS. 
To show the certificate renewal progress I have setup a local CA with [Pebble][Pebble] and issued a certificate that's only valid for 1 Minute.

https://user-images.githubusercontent.com/38843153/180786839-adcba9db-b883-4399-a4e4-a6e924b51df3.mov

## Usage

First you need to compile CoreDNS with this plugin

```
# Clone CoreDNS
git clone https://github.com/coredns/coredns
cd coredns

# replace the original tls plugin with this tlsplus plugin
sed -i 's/tls:tls/tls:github.com\/mariuskimina\/coredns-tlsplus/g' plugin.cfg

# Get the module
go get github.com/mariuskimmina/coredns-tlsplus

# Tidy modules
go mod tidy

# Compile
go build
```

### Automatic

To use this plugin for automatic certificate management you have to fullfill the following requirements:
* Own a domain
* Setup CoreDNS on a publicly reachable IP
* Setup CoreDNS as the authoritative DNS server for your domain
* Port 53 - While CoreDNS may serve DNS over TLS on any port, during startup the plugin will use port 53 to solve the [ACME Challenge][Challenge]

When CoreDNS is setup as the authoritative DNS Server for a domain such as `example.com`, all you need to add to your corefile to start serving DoT or DoH is the following:

~~~ txt
tls acme {
    domain example.com
}
~~~

full example configuration, serving dns over both UPD (Port 53) and HTTPS (Port 443) and TLS (Port 853). 
In this example the dns server, will obtain a certificate for `ns1.mydomain.com`.

```
tls://mydomain.com {
    tls acme {
        domain ns1.mydomain.com
    }
    hosts {
        xxx.xxx.xxx.xxx mydomain.com
        xxx.xxx.xxx.xxx ns1.mydomain.com
    }
}

https://mydomain.com {
    tls acme {
        domain ns1.mydomain.com
    }
    hosts {
        xxx.xxx.xxx.xxx mydomain.com
        xxx.xxx.xxx.xxx ns1.mydomain.com
    }
}

mydomain.com {
    hosts {
        xxx.xxx.xxx.xxx mydomain.com
        xxx.xxx.xxx.xxx ns1.mydomain.com
    }
}
```


### Manual
You can provide a certificate and key manually. If this is your use-case you don't need this plugin, use the internal tls plugin of coredns

~~~ txt
tls CERT KEY [CA]
~~~

Parameter CA is optional. If not set, system CAs can be used to verify the client certificate

## Test setup

All test can be run locally with

```
go test ./...
```

Port 14000 (ACME Server) and 1053 (CoreDNS) are required for integration tests


## History

The original issue where the ideas for this plugin were first discussed can be found here: https://github.com/coredns/coredns/issues/3460  
The author has a Corefile like this:

```
https://www.mydomain.com {
    bind myip
    hosts {
        10.6.6.2 sms.service
        10.6.6.3 search.service
    }
}
```

asking how he could setup automatic tls certificates. At the time that couldn't be done, but now with this plugin, it can.
Assuming that he has setup his CoreDNS server as the authoritative DNS Server for `mydomain` running at ns1.mydomain.com.
The following Corefile should automatically obtain a certificate from let's encrypt and keep it renewed at all times.

```
https://mydomain.com {
    tls acme {
        domain ns1.mydomain.com
    }
    bind myip
    hosts {
        10.6.6.2 sms.mydomain.com
        10.6.6.3 search.mydomain.com
    }
}
```

## References
ACME RFC: https://datatracker.ietf.org/doc/html/rfc8555  
Pebble: https://github.com/letsencrypt/pebble  
ACME Challenges: https://letsencrypt.org/docs/challenge-types/  

[ACME]: https://datatracker.ietf.org/doc/html/rfc8555
[Let's Encrypt]: https://letsencrypt.org/
[client-server]: https://en.wikipedia.org/wiki/Client%E2%80%93server_model
[Pebble]: https://github.com/letsencrypt/pebble
[Challenge]: https://letsencrypt.org/docs/challenge-types/  

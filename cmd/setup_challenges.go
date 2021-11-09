package cmd

import (
	"net"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/challenge/tkauth01"
	"github.com/go-acme/lego/v4/challenge/tlsalpn01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/log"
	"github.com/go-acme/lego/v4/providers/dns"
	"github.com/go-acme/lego/v4/providers/http/memcached"
	"github.com/go-acme/lego/v4/providers/http/webroot"
	"github.com/urfave/cli"
)

func setupChallenges(ctx *cli.Context, client *lego.Client) {
	if !ctx.GlobalBool("http") && !ctx.GlobalBool("tls") && !ctx.GlobalIsSet("dns") && !ctx.GlobalIsSet("tkauth") {
		log.Fatal("No challenge selected. You must specify at least one challenge: `--http`, `--tls`, `--dns`, `--tkauth` .")
	}

	if ctx.GlobalBool("http") {
		err := client.Challenge.SetHTTP01Provider(setupHTTPProvider(ctx))
		if err != nil {
			log.Fatal(err)
		}
	}

	if ctx.GlobalBool("tls") {
		err := client.Challenge.SetTLSALPN01Provider(setupTLSProvider(ctx))
		if err != nil {
			log.Fatal(err)
		}
	}

	if ctx.GlobalIsSet("dns") {
		setupDNS(ctx, client)
	}

	if ctx.GlobalIsSet("tkauth") {
		setupTkauth(ctx, client)
	}

}

func setupHTTPProvider(ctx *cli.Context) challenge.Provider {
	switch {
	case ctx.GlobalIsSet("http.webroot"):
		ps, err := webroot.NewHTTPProvider(ctx.GlobalString("http.webroot"))
		if err != nil {
			log.Fatal(err)
		}
		return ps
	case ctx.GlobalIsSet("http.memcached-host"):
		ps, err := memcached.NewMemcachedProvider(ctx.GlobalStringSlice("http.memcached-host"))
		if err != nil {
			log.Fatal(err)
		}
		return ps
	case ctx.GlobalIsSet("http.port"):
		iface := ctx.GlobalString("http.port")
		if !strings.Contains(iface, ":") {
			log.Fatalf("The --http switch only accepts interface:port or :port for its argument.")
		}

		host, port, err := net.SplitHostPort(iface)
		if err != nil {
			log.Fatal(err)
		}

		srv := http01.NewProviderServer(host, port)
		if header := ctx.GlobalString("http.proxy-header"); header != "" {
			srv.SetProxyHeader(header)
		}
		return srv
	case ctx.GlobalBool("http"):
		srv := http01.NewProviderServer("", "")
		if header := ctx.GlobalString("http.proxy-header"); header != "" {
			srv.SetProxyHeader(header)
		}
		return srv
	default:
		log.Fatal("Invalid HTTP challenge options.")
		return nil
	}
}

func setupTLSProvider(ctx *cli.Context) challenge.Provider {
	switch {
	case ctx.GlobalIsSet("tls.port"):
		iface := ctx.GlobalString("tls.port")
		if !strings.Contains(iface, ":") {
			log.Fatalf("The --tls switch only accepts interface:port or :port for its argument.")
		}

		host, port, err := net.SplitHostPort(iface)
		if err != nil {
			log.Fatal(err)
		}

		return tlsalpn01.NewProviderServer(host, port)
	case ctx.GlobalBool("tls"):
		return tlsalpn01.NewProviderServer("", "")
	default:
		log.Fatal("Invalid HTTP challenge options.")
		return nil
	}
}

func setupDNS(ctx *cli.Context, client *lego.Client) {
	provider, err := dns.NewDNSChallengeProviderByName(ctx.GlobalString("dns"))
	if err != nil {
		log.Fatal(err)
	}

	servers := ctx.GlobalStringSlice("dns.resolvers")
	err = client.Challenge.SetDNS01Provider(provider,
		dns01.CondOption(len(servers) > 0,
			dns01.AddRecursiveNameservers(dns01.ParseNameservers(ctx.GlobalStringSlice("dns.resolvers")))),
		dns01.CondOption(ctx.GlobalBool("dns.disable-cp"),
			dns01.DisableCompletePropagationRequirement()),
		dns01.CondOption(ctx.GlobalIsSet("dns-timeout"),
			dns01.AddDNSTimeout(time.Duration(ctx.GlobalInt("dns-timeout"))*time.Second)),
	)
	if err != nil {
		log.Fatal(err)
	}
}

func setupTkauth(ctx *cli.Context, client *lego.Client) {

	// We now have two types.  SPC based for STIR/SHAKEN and Delegate cert one which will not
	// have any of these config options.  Do this based on if tkauth.tnauthlist is set
	tnauthlist := ctx.GlobalString("tkauth.tnauthlist")
	if tnauthlist == "" {
		ctx.GlobalString("tkauth.stipa-user")
		if !ctx.GlobalIsSet("tkauth.stipa-user") {
			log.Warnf("tkauth.stipa-user not set.")
		}
		if !ctx.GlobalIsSet("tkauth.stipa-password") {
			log.Warnf("tkauth.stipa-password not set.")
		}
		if !ctx.GlobalIsSet("tkauth.SPC") {
			log.Warnf("tkauth.SPC not set.")
		}

		tkauth01.SetStiPaUser(ctx.GlobalString("tkauth.stipa-user"))
		tkauth01.SetStiPaPassword(ctx.GlobalString("tkauth.stipa-password"))
		tkauth01.SetStiPaUrl(ctx.GlobalString("tkauth.stipa"))
		tkauth01.SetSPC(ctx.GlobalString("tkauth.SPC"))
	} else {
		tkauth01.SetTNAuthList(tnauthlist)
	}

	err := client.Challenge.SetTkauthProvider()
	if err != nil {
		log.Println("Error create Tkauth Provider ", err)
	}

	log.Println("Using tkauth challenge")

}

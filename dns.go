package mcassoc

import (
	"context"
	"fmt"
	"net"

	"github.com/miekg/dns"

	"google.golang.org/appengine/socket"
)

const resolver = "8.8.8.8:53"

func lookupIP(ctx context.Context, host string) (addrs []net.IP, err error) {
	return socket.LookupIP(ctx, host)
}

func lookupTXT(ctx context.Context, host string) ([]string, error) {
	msg := &dns.Msg{
		Question: []dns.Question{{
			Name:   dns.Fqdn(host),
			Qtype:  dns.TypeTXT,
			Qclass: uint16(dns.ClassINET),
		}},
	}
	msg.Id = dns.Id()

	conn, err := socket.Dial(ctx, "udp", resolver)
	if err != nil {
		return nil, fmt.Errorf("socket.Dial(%v, %v): %v", "udp", resolver, err)
	}
	defer conn.Close()

	dnsc := &dns.Conn{Conn: conn}
	defer dnsc.Close()
	if err := dnsc.WriteMsg(msg); err != nil {
		return nil, fmt.Errorf("dnsc.WriteMsg(%v): %v", msg, err)
	}
	rmsg, err := dnsc.ReadMsg()
	if err != nil {
		return nil, fmt.Errorf("dnsc.ReadMsg(): %v", err)
	}

	var answers []string
	for _, m := range rmsg.Answer {
		m, ok := m.(*dns.TXT)
		if !ok {
			continue
		}

		if m.Hdr.Name != msg.Question[0].Name {
			continue
		}
		answers = append(answers, m.Txt...)
	}
	return answers, nil
}

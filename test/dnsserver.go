package main

import (
	"log"
	"time"
	"fmt"
	"github.com/miekg/dns"
)

func main() {

	dns.Handle(".", dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)

		var rr dns.RR
		var err error
		
			switch r.Question[0].Qtype {
			case dns.TypeA:
				rr, err = dns.NewRR(fmt.Sprintf("%s A 127.0.0.1",r.Question[0].Name ))
			case dns.TypeAAAA:
				rr, err = dns.NewRR(fmt.Sprintf("%s AAAA ::1",r.Question[0].Name))
			}
			if err != nil {
				log.Fatalf("Failed to create RR %s\n", err)
			}
			m.Answer = append(m.Answer, rr)
		

		time.Sleep(50 * time.Millisecond)

		if err = w.WriteMsg(m); err != nil {
			log.Fatalf("Failed to write msg %s\n", err)
		}

	}))

	protocol := "udp"

	server := &dns.Server{Addr: ":9443", Net: protocol}
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Failed to start dns server %s\n", err)
	}
	defer server.Shutdown()
}

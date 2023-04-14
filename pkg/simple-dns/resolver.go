package simpleDns

import (
	"bufio"
	"crypto/rand"
	"fmt"
	"math/big"
	"net"

	"golang.org/x/net/dns/dnsmessage"
)

var ROOT_SERVERS = []string{
	"192.5.5.241",
	"192.112.36.4",
	"198.97.190.53",
	"192.36.148.17",
	"192.58.128.30",
	"193.0.14.129",
	"199.7.83.42",
	"202.12.27.33",
	"198.41.0.4",
	"199.9.14.201",
	"192.33.4.12",
	"199.7.91.13",
	"192.203.230.10",
}

func getRootServers(serverList []string) []net.IP {
	var IPs []net.IP
	for _, server := range serverList {
		IPs = append(IPs, net.ParseIP(server))
	}

	return IPs
}

func HandleDNSPacket(pconn net.PacketConn, addr net.Addr, buf []byte) {
	if err := handleDNSPacket(pconn, addr, buf); err != nil {
		fmt.Printf("handleDNSPacket error [%s]: %s\n", addr.String(), err)
	}

}
func handleDNSPacket(pconn net.PacketConn, addr net.Addr, buf []byte) error {
	p := dnsmessage.Parser{}
	header, err := p.Start(buf)
	if err != nil {
		return err
	}

	question, err := p.Question()
	if err != nil {
		return err
	}

	response, err := dnsQueryResponse(getRootServers(ROOT_SERVERS), question)
	if err != nil {
		return err
	}

	response.Header.ID = header.ID

	responseBuffer, err := response.Pack()
	if err != nil {
		return err
	}

	_, err = pconn.WriteTo(responseBuffer, addr)
	if err != nil {
		return err
	}

	return nil
}

func dnsQueryResponse(serverList []net.IP, question dnsmessage.Question) (*dnsmessage.Message, error) {

	for {
		parser, header, err := dnsQuery(serverList, question)
		if err != nil {
			return nil, err
		}
		parsedAnswers, err := parser.AllAnswers()

		if err != nil {
			return nil, err
		}

		if header.Authoritative {
			return &dnsmessage.Message{
				Header: dnsmessage.Header{
					Response: true,
				},
				Answers: parsedAnswers,
			}, nil
		}

		authorities, err := parser.AllAuthorities()
		if err != nil {
			return nil, err
		}

		if len(authorities) == 0 {
			return &dnsmessage.Message{
				Header: dnsmessage.Header{
					RCode: dnsmessage.RCodeNameError,
				},
			}, nil
		}

		nameservers := make([]string, len(authorities))

		for k, authority := range authorities {
			if authority.Header.Type == dnsmessage.TypeNS {
				nameservers[k] = authority.Body.(*dnsmessage.NSResource).NS.String()
			}
		}
		additionals, err := parser.AllAdditionals()
		if err != nil {
			return nil, err
		}

		newResolverServersFound := false

		serverList = []net.IP{}
		for _, additional := range additionals {
			// fmt.Printf("Additional: %+v\n", additional)
			if additional.Header.Type == dnsmessage.TypeA {
				for _, nameserver := range nameservers {
					if additional.Header.Name.String() == nameserver {
						fmt.Printf("NAMESERVER\t\t%s\t\t%v\n", nameserver, additional.Body.(*dnsmessage.AResource).A[:])
						newResolverServersFound = true
						serverList = append(serverList, additional.Body.(*dnsmessage.AResource).A[:])
					}
				}
			}
		}
		if !newResolverServersFound {
			for _, nameserver := range nameservers {
				if !newResolverServersFound {
					response, err := dnsQueryResponse(getRootServers(ROOT_SERVERS), dnsmessage.Question{
						Name:  dnsmessage.MustNewName(nameserver),
						Type:  dnsmessage.TypeA,
						Class: dnsmessage.ClassINET,
					})
					if err != nil {
						fmt.Printf("warning: lookup of nameserver %s failed: %err\n", nameserver, err)
					} else {
						newResolverServersFound = true
						for _, answer := range response.Answers {
							if answer.Header.Type == dnsmessage.TypeA {
								serverList = append(serverList, answer.Body.(*dnsmessage.AResource).A[:])
							}
						}
					}
				}
			}
		}
	}
}

func dnsQuery(serverList []net.IP, q dnsmessage.Question) (*dnsmessage.Parser, *dnsmessage.Header, error) {
	fmt.Printf("outgoing DNS query [%s]\n", q.Name.String())
	max := ^uint16(0)
	randomID, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return nil, nil, err
	}
	message := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:       uint16(randomID.Int64()),
			OpCode:   dnsmessage.OpCode(0),
			Response: false,
		},
		Questions: []dnsmessage.Question{q},
	}
	buf, err := message.Pack()
	if err != nil {
		return nil, nil, err
	}
	var conn net.Conn
	for _, server := range serverList {
		conn, err = net.Dial("udp", server.String()+":53")
		if err == nil {
			break
		}
	}

	if conn == nil {
		return nil, nil, fmt.Errorf("Failed to make connection to servers: %s", err)
	}

	defer conn.Close()

	_, err = conn.Write(buf)
	if err != nil {
		return nil, nil, err
	}

	answer := make([]byte, 512)
	n, err := bufio.NewReader(conn).Read(answer)
	if err != nil {
		return nil, nil, err
	}

	var p dnsmessage.Parser
	header, err := p.Start(answer[:n])
	if err != nil {
		return nil, nil, fmt.Errorf("parser start error: %s", err)
	}

	questions, err := p.AllQuestions()
	if err != nil {
		return nil, nil, err
	}

	if len(questions) != len(message.Questions) {
		return nil, nil, fmt.Errorf("answer packet doesn't have the same amount of questions")
	}

	if err = p.SkipAllQuestions(); err != nil {
		return nil, nil, err
	}

	return &p, &header, nil
}

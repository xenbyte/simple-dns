package simpleDns

import (
	"math/rand"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.org/x/net/dns/dnsmessage"
)

// This struct should satisfy the methods for interface net.PacketConn
type MockPacketConnection struct{}

func (m *MockPacketConnection) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	return 0, nil
}

func (m *MockPacketConnection) Close() error {
	return nil
}

func (m *MockPacketConnection) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	return 0, nil, nil
}

func (m *MockPacketConnection) LocalAddr() net.Addr {
	return nil
}

func (m *MockPacketConnection) SetDeadline(t time.Time) error {
	return nil
}

func (m *MockPacketConnection) SetReadDeadline(t time.Time) error {
	return nil
}

func (m *MockPacketConnection) SetWriteDeadline(t time.Time) error {
	return nil
}

func TestHandleDNSPacket(t *testing.T) {
	names := []string{"www.cloudflare.com.", "www.digikala.com."}
	for _, name := range names {
		message := dnsmessage.Message{
			Header: dnsmessage.Header{
				ID:               uint16(rand.Intn(int(^uint16(0)))),
				OpCode:           dnsmessage.OpCode(0),
				RCode:            dnsmessage.RCode(0),
				Response:         false,
				AuthenticData:    false,
				RecursionDesired: false,
			},
			Questions: []dnsmessage.Question{
				{
					Name:  dnsmessage.MustNewName(name),
					Type:  dnsmessage.TypeA,
					Class: dnsmessage.ClassINET,
				},
			},
		}
		buf, err := message.Pack()
		assert.NoError(t, err)
		err = handleDNSPacket(&MockPacketConnection{}, &net.IPAddr{
			IP: net.ParseIP("127.0.0.1"),
		}, buf)
		assert.NoError(t, err)

	}
}

func TestOutGoingDNSQuery(t *testing.T) {
	q := dnsmessage.Question{
		Name:  dnsmessage.MustNewName("www.cloudflare.com."),
		Type:  dnsmessage.TypeNS,
		Class: dnsmessage.ClassINET,
	}

	rootServers := ROOT_SERVERS
	servers := []net.IP{
		net.ParseIP(rootServers[0]),
	}

	dnsAnswer, header, err := dnsQuery(servers, q)
	assert.NoError(t, err)
	assert.NotEqual(t, header, nil)
	assert.NotEqual(t, dnsAnswer, nil)
	assert.Equal(t, header.RCode, dnsmessage.RCodeSuccess)

	err = dnsAnswer.SkipAllAnswers()
	assert.NoError(t, err)
	parsedAuthorities, err := dnsAnswer.AllAuthorities()
	assert.NoError(t, err)
	assert.NotEqual(t, len(parsedAuthorities), 0)
}

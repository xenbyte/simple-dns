package main

import (
	"fmt"
	"net"
	simpleDns "simple-dns/pkg/simple-dns"
)

func main() {
	packetConn, err := net.ListenPacket("udp", "0.0.0.0:53")
	if err != nil {
		panic(err)
	}
	defer packetConn.Close()
	fmt.Printf("DNS Server started listen on %s\n", packetConn.LocalAddr())

	for {
		buf := make([]byte, 512)
		n, addr, err := packetConn.ReadFrom(buf[:])
		if err != nil {
			fmt.Printf("read error from %s: %s\n", addr.String(), err)
			continue
		}
		go simpleDns.HandleDNSPacket(packetConn, addr, buf[:n])
	}
}

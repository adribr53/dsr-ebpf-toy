package main

import (
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"github.com/praserx/ipconv"
)

func main() {
	var (
		serviceDsrIpv4 string
	)
	serviceDsrIpv4 = "1.1.1.1"

	m, err := ebpf.LoadPinnedMap("/sys/fs/bpf/service_dsr_ipv4", nil)
	if err != nil {
		fmt.Printf("failed to load pinned map: %s", err)
	}
	vip, err := ipconv.IPv4ToInt(net.ParseIP(serviceDsrIpv4))
	if err != nil {
		fmt.Printf("failed to convert %s to int", serviceDsrIpv4)
		panic(err)
	}
	err = m.Update(uint32(0), vip, ebpf.UpdateAny)
	if err != nil {
		panic(fmt.Errorf("put failed: %w", err))
	}
	fmt.Println("Hello, DSR eBPF Toy!!")
	fmt.Println("map populated, press enter to exit")
	fmt.Scanln()
}

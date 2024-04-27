//go:build linux

package ebpf

import (
	"encoding/binary"
	"net"

	"github.com/asavie/xdp"
	"github.com/cilium/ebpf"
)

type TCPHijackProgram struct {
	*xdp.Program
	whitelist *ebpf.Map
	conntrack *ebpf.Map
	mode      *ebpf.Map
}

// ethhdr + iphdr + tcphdr
type Connstrack [54]byte

//go:generate $HOME/go/bin/bpf2go -target bpfel -no-strip tcp_hijack tcp_hijack.c -- -I/usr/include/ -I./include -O2
func NewTCPHijackProgram(options *ebpf.CollectionOptions) (*TCPHijackProgram, error) {
	spec, err := loadTcp_hijack()
	if err != nil {
		return nil, err
	}

	var prog tcp_hijackObjects
	err = spec.LoadAndAssign(&prog, options)
	if err != nil {
		return nil, err
	}

	return &TCPHijackProgram{
		Program: &xdp.Program{
			Queues:  prog.QidconfMap,
			Sockets: prog.XsksMap,
			Program: prog.XdpRedirectProg,
		},
		whitelist: prog.WhitelistMap,
		conntrack: prog.ConntrackMap,
		mode:      prog.ModeMap,
	}, nil
}

func (p *TCPHijackProgram) AddToWhitelist(ip net.IP, port int) error {
	return p.whitelist.Put(GetKey(ip, port), uint32(1))
}

func (p *TCPHijackProgram) RemoveFromWhitelist(ip net.IP, port int) error {
	return p.whitelist.Delete(GetKey(ip, port))
}

func (p *TCPHijackProgram) SetServerMode() error {
	return p.mode.Put(uint32(1), uint32(1))
}

func (p *TCPHijackProgram) GetConntrackData(ip net.IP, port int) []byte {
	return p.GetConntrackDataByKey(GetKey(ip, port))
}

func (p *TCPHijackProgram) GetConntrackDataByKey(key uint64) []byte {
	var connstrack Connstrack

	err := p.conntrack.Lookup(key, &connstrack)
	if err != nil {
		return nil
	}
	return connstrack[:]
}

func GetKey(ip net.IP, port int) uint64 {
	key := uint64(binary.BigEndian.Uint32(ip.To4()))
	key = key<<16 | uint64(port)
	return key
}

func RetrieveIPPort(key uint64) (net.IP, int) {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, uint32(key>>16))
	port := int(key & 0xffff)
	return ip, port
}

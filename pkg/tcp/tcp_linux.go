package tcp

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var _ net.PacketConn = (*TCPConn)(nil)

var (
	errTimeout   = errors.New("timeout")
	errNotEnough = errors.New("not enough")
)

func (conn *TCPConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	var timer *time.Timer
	var deadline <-chan time.Time
	if d, ok := conn.readDeadline.Load().(time.Time); ok && !d.IsZero() {
		timer = time.NewTimer(time.Until(d))
		defer timer.Stop()
		deadline = timer.C
	}

	select {
	case <-deadline:
		return 0, nil, errTimeout
	case <-conn.die:
		return 0, nil, io.EOF
	case pkt := <-conn.inbound:
		n = copy(p, pkt.recv)
		return n, pkt.addr, nil
	}
}

func (conn *TCPConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	var timer *time.Timer
	var deadline <-chan time.Time
	if d, ok := conn.readDeadline.Load().(time.Time); ok && !d.IsZero() {
		timer = time.NewTimer(time.Until(d))
		defer timer.Stop()
		deadline = timer.C
	}

	select {
	case <-deadline:
		return 0, errTimeout
	case <-conn.die:
		return 0, io.EOF
	default:
	}

	raddr, err := net.ResolveTCPAddr("tcp4", addr.String())
	if err != nil {
		return 0, err
	}

	conntrack := conn.getHeader(raddr.IP, raddr.Port)
	if conntrack == nil {
		return 0, fmt.Errorf("connection not found")
	}

	pkt := gopacket.NewPacket(conntrack, layers.LayerTypeEthernet, gopacket.Default)
	ethFrame := pkt.LinkLayer().(*layers.Ethernet)
	ipFrame := pkt.NetworkLayer().(*layers.IPv4)
	tcpFrame := pkt.TransportLayer().(*layers.TCP)

	ethFrame.SrcMAC, ethFrame.DstMAC = ethFrame.DstMAC, ethFrame.SrcMAC
	ipFrame.SrcIP, ipFrame.DstIP = ipFrame.DstIP, ipFrame.SrcIP
	ipFrame.TOS = conn.dscp

	tcpFrame.SrcPort, tcpFrame.DstPort = tcpFrame.DstPort, tcpFrame.SrcPort
	tcpFrame.SetNetworkLayerForChecksum(ipFrame)
	tcpFrame.PSH = true
	tcpFrame.ACK = true

	buf := conn.getBuffer()
	buf.Clear()
	err = gopacket.SerializeLayers(buf, *conn.opts, ethFrame, ipFrame, tcpFrame, gopacket.Payload(p))
	if err != nil {
		return 0, err
	}

	pkt = gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	log.Printf("pkt: %v", pkt)

	select {
	case <-deadline:
		return 0, errTimeout
	case <-conn.die:
		return 0, io.EOF
	case conn.outbound <- message{send: buf, addr: addr}:
	}

	return len(p), nil
}

// Close closes the connection.
// Any blocked ReadFrom or WriteTo operations will be unblocked and return errors.
func (conn *TCPConn) Close() error {
	conn.closeFunc(conn.key)

	if conn.listener != nil {
		return conn.listener.Close()
	}

	return conn.conn.Close()
}

func (conn *TCPConn) LocalAddr() net.Addr {
	if conn.listener != nil {
		return conn.listener.Addr()
	}
	return conn.conn.LocalAddr()
}

func (conn *TCPConn) SetDeadline(t time.Time) error {
	if err := conn.SetReadDeadline(t); err != nil {
		return err
	}

	if err := conn.SetWriteDeadline(t); err != nil {
		return err
	}

	return nil
}

func (conn *TCPConn) SetReadDeadline(t time.Time) error {
	conn.readDeadline.Store(t)
	return nil
}

func (conn *TCPConn) SetWriteDeadline(t time.Time) error {
	conn.writeDeadline.Store(t)
	return nil
}

func (conn *TCPConn) SetDSCP(dscp int) error {
	conn.dscp = uint8(dscp << 2)
	// conn.ipHeader.TOS =
	return nil
}

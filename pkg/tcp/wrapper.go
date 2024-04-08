package tcp

import (
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/asavie/xdp"
	cebpf "github.com/cilium/ebpf"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/maypok86/otter"
	"github.com/vishvananda/netlink"

	"github.com/mYmNeo/xdp/ebpf"
)

type message struct {
	recv []byte
	send gopacket.SerializeBuffer
	addr net.Addr
}

type TCPWrapper struct {
	xdp      *TCPWrapperXDP
	conns    otter.Cache[uint64, *TCPConn]
	outbound chan message
	stop     chan struct{}
	bufPool  *sync.Pool

	// serialization
	opts gopacket.SerializeOptions
}

type TCPWrapperXDP struct {
	link netlink.Link
	xsks []*xdp.Socket
	prog *ebpf.TCPHijackProgram
}

type TCPConn struct {
	die     chan struct{}
	dieOnce sync.Once

	// deadlines
	readDeadline  atomic.Value
	writeDeadline atomic.Value

	listener net.Listener
	conn     net.Conn
	key      uint64
	dscp     uint8

	// packets channel
	inbound  chan message
	outbound chan message
	opts     *gopacket.SerializeOptions

	getHeader func(ip net.IP, port int) []byte
	getBuffer func() gopacket.SerializeBuffer
	closeFunc func(key uint64)
}

var (
	xdpProg          *TCPWrapperXDP
	xdpInitOnce      sync.Once
	defaultXDPOption = &xdp.SocketOptions{
		NumFrames:              4096,
		FrameSize:              2048,
		FillRingNumDescs:       2048,
		CompletionRingNumDescs: 2048,
		RxRingNumDescs:         2048,
		TxRingNumDescs:         2048,
	}
)

func NewTCPWrapper(interfaceName string) (*TCPWrapper, error) {
	iface, err := netlink.LinkByName(interfaceName)
	if err != nil {
		return nil, err
	}

	if err = removeXDP(iface); err != nil {
		return nil, err
	}

	xdpInitOnce.Do(func() {
		xdpProg = &TCPWrapperXDP{
			link: iface,
			xsks: make([]*xdp.Socket, min(iface.Attrs().NumTxQueues, iface.Attrs().NumRxQueues)),
		}

		if err := xdpProg.Init(); err != nil {
			panic(err)
		}
	})

	connsTracker, err := otter.MustBuilder[uint64, *TCPConn](math.MaxUint16).Build()
	if err != nil {
		return nil, err
	}

	baseWrapper := &TCPWrapper{
		xdp:      xdpProg,
		conns:    connsTracker,
		outbound: make(chan message, defaultXDPOption.NumFrames*len(xdpProg.xsks)),
		stop:     make(chan struct{}),
		bufPool: &sync.Pool{
			New: func() interface{} {
				return gopacket.NewSerializeBuffer()
			},
		},
		opts: gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		},
	}

	baseWrapper.readLoop()
	baseWrapper.writeLoop()

	return baseWrapper, nil
}

func (w *TCPWrapper) Shutdown() (err error) {
	close(w.stop)

	if w.xdp == nil {
		return
	}

	for i := 0; i < len(w.xdp.xsks); i++ {
		if w.xdp.xsks[i] == nil {
			continue
		}

		err = w.xdp.prog.Unregister(i)
		if err != nil {
			return
		}
	}

	err = w.xdp.prog.Detach(w.xdp.link.Attrs().Index)
	if err != nil {
		return
	}

	err = w.xdp.prog.Close()
	if err != nil {
		return
	}

	w.conns.Close()

	return
}

func (w *TCPWrapper) readLoop() {
	for i := 0; i < len(w.xdp.xsks); i++ {
		go func(xsk *xdp.Socket) {
			defer log.Printf("%d readLoop() exited\n", xsk.FD())

			var (
				numRx   int
				numFill int
				conn    *TCPConn
				ok      bool
			)

			for {
				select {
				case <-w.stop:
					return
				default:
				}

				if numFill = xsk.NumFreeFillSlots(); numFill > 0 {
					xsk.Fill(xsk.GetDescs(numFill, true))
				}

				// Wait for incoming packets
				xsk.Poll(1000)
				numRx = xsk.NumReceived()
				if numRx == 0 {
					continue
				}

				// Consume the descriptors filled with received frames
				// from the Rx ring queue.
				rxDescs := xsk.Receive(numRx)
				for i := 0; i < len(rxDescs); i++ {
					pkt := gopacket.NewPacket(xsk.GetFrame(rxDescs[i]), layers.LayerTypeEthernet, gopacket.Default)
					ip := pkt.NetworkLayer().(*layers.IPv4)
					tcp := pkt.TransportLayer().(*layers.TCP)

					conn, ok = w.conns.Get(ebpf.GetKey(ip.SrcIP, int(tcp.SrcPort)))
					if !ok {
						conn, ok = w.conns.Get(ebpf.GetKey(ip.DstIP, int(tcp.DstPort)))
					}

					if ok {
						log.Printf("received packet from %s:%d to %s:%d, size:%d\n", ip.SrcIP, tcp.SrcPort, ip.DstIP, tcp.DstPort, len(tcp.Payload))
						m := message{
							recv: tcp.Payload,
							addr: &net.TCPAddr{
								IP:   ip.SrcIP,
								Port: int(tcp.SrcPort),
							},
						}

						select {
						case <-conn.die:
						case conn.inbound <- m:
						default:
							log.Printf("inbound is full, size: %d\n", cap(conn.inbound))
						}
					}
				}
			}
		}(w.xdp.xsks[i])
	}
}

func (w *TCPWrapper) writeLoop() {
	for i := 0; i < len(w.xdp.xsks); i++ {
		go func(xsk *xdp.Socket) {
			defer log.Printf("%d writeLoop() exited\n", xsk.FD())

			var (
				numTx int
				i     int
				empty bool
			)
			for {
				pkt := <-w.outbound
				for numTx = xsk.NumFreeTxSlots(); numTx < 1; {
					log.Printf("%d NumFreeTxSlots() is 0\n", xsk.FD())
					time.Sleep(time.Millisecond * 100)
				}

				i = 0
				txDescs := xsk.GetDescs(numTx, false)
				txDescs[i].Len = uint32(copy(xsk.GetFrame(txDescs[i]), pkt.send.Bytes()))
				w.bufPool.Put(pkt.send)

				for i = 1; i < numTx; i++ {
					select {
					case <-w.stop:
						return
					case pkt = <-w.outbound:
						txDescs[i].Len = uint32(copy(xsk.GetFrame(txDescs[i]), pkt.send.Bytes()))
						w.bufPool.Put(pkt.send)
					default:
						empty = true
					}

					if empty {
						break
					}
				}

				xsk.Transmit(txDescs[:i])
				xsk.Poll(1000)
			}
		}(w.xdp.xsks[i])
	}
}

func (w *TCPWrapper) getBuffer() gopacket.SerializeBuffer {
	return w.bufPool.Get().(gopacket.SerializeBuffer)
}

func (w *TCPWrapper) Dial(network, address string) (*TCPConn, error) {
	conn, err := net.Dial(network, address)
	if err != nil {
		return nil, err
	}

	tcpAddr, ok := conn.LocalAddr().(*net.TCPAddr)
	if !ok {
		return nil, fmt.Errorf("not a tcp addres")
	}
	w.xdp.prog.AddToWhitelist(tcpAddr.IP, tcpAddr.Port)

	tcpconn := &TCPConn{
		outbound:  w.outbound,
		inbound:   make(chan message, 1024),
		die:       make(chan struct{}),
		conn:      conn,
		key:       ebpf.GetKey(tcpAddr.IP, tcpAddr.Port),
		opts:      &w.opts,
		closeFunc: w.conns.Delete,
		getBuffer: w.getBuffer,
		getHeader: func(ip net.IP, port int) []byte {
			return w.xdp.prog.GetConnstrackData(ip, port)
		},
	}

	w.conns.Set(tcpconn.key, tcpconn)
	go io.Copy(io.Discard, conn)

	return tcpconn, nil
}

func (w *TCPWrapper) Listen(network, address string) (*TCPConn, error) {
	listener, err := net.Listen(network, address)
	if err != nil {
		return nil, err
	}

	laddr, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		return nil, fmt.Errorf("Local address is not a TCP")
	}

	tcpconn := &TCPConn{
		outbound:  w.outbound,
		inbound:   make(chan message, 1024),
		die:       make(chan struct{}),
		listener:  listener,
		key:       ebpf.GetKey(laddr.IP, laddr.Port),
		opts:      &w.opts,
		getBuffer: w.getBuffer,
		closeFunc: w.conns.Delete,
	}
	w.xdp.prog.AddToWhitelist(laddr.IP, laddr.Port)

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}

			raddr, ok := conn.LocalAddr().(*net.TCPAddr)
			if !ok {
				return
			}

			log.Printf("accepted connection from %s:%d\n", raddr.IP, raddr.Port)
			w.conns.Set(ebpf.GetKey(raddr.IP, raddr.Port), tcpconn)

			go io.Copy(io.Discard, conn)
		}
	}()

	return tcpconn, nil
}

func (x *TCPWrapperXDP) Init() (err error) {
	x.prog, err = ebpf.NewTCPHijackProgram(&cebpf.CollectionOptions{})
	if err != nil {
		return err
	}

	if err = x.prog.Attach(x.link.Attrs().Index); err != nil {
		return err
	}

	failed := 0
	for i := 0; i < len(x.xsks); i++ {
		x.xsks[i], err = xdp.NewSocket(x.link.Attrs().Index, i, defaultXDPOption)
		if err != nil {
			log.Printf("xdp.NewSocket() failed: %v\n", err)
			failed++
		}
	}

	if failed == len(x.xsks) {
		return fmt.Errorf("no xdp sockets could be created")
	}

	for i := 0; i < len(x.xsks); i++ {
		err = x.prog.Register(i, x.xsks[i].FD())
		if err != nil {
			return err
		}
	}

	return nil
}

func isXdpAttached(link netlink.Link) bool {
	if link.Attrs() != nil && link.Attrs().Xdp != nil && link.Attrs().Xdp.Attached {
		return true
	}
	return false
}

func removeXDP(link netlink.Link) (err error) {
	if !isXdpAttached(link) {
		return nil
	}

	if err = netlink.LinkSetXdpFd(link, -1); err != nil {
		return fmt.Errorf("netlink.LinkSetXdpFd(link, -1) failed: %v", err)
	}

	return
}

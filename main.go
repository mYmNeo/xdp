package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mYmNeo/xdp/pkg/tcp"
)

func main() {
	var linkName string
	var addr string
	var mode string

	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)

	flag.StringVar(&linkName, "linkname", "enp3s0", "The network link on which rebroadcast should run on.")
	flag.StringVar(&addr, "addr", "0.0.0.0", "The address connect or listen")
	flag.StringVar(&mode, "mode", "client", "The mode of operation (server or client)")
	flag.Parse()

	go func() {
		http.ListenAndServe("127.0.0.1:8080", nil)
	}()

	// Remove the XDP BPF program on interrupt.
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		os.Exit(1)
	}()

	buf := make([]byte, 1024)
	timer := time.NewTicker(time.Second)
	totalBytes := 0

	if mode == "client" {
		w, err := tcp.NewTCPWrapper(linkName)
		if err != nil {
			panic(err)
		}
		defer w.Shutdown()

		tcpAddr, _ := net.ResolveTCPAddr("tcp", addr)
		conn, err := w.Dial("tcp", addr)
		if err != nil {
			panic(err)
		}

		log.Printf("Local address: %s\n", conn.LocalAddr())
		for {
			select {
			case <-timer.C:
				log.Printf("client: %.2f MBytes\n", float64(totalBytes)/1024)
				totalBytes = 0
			default:
			}

			n, err := conn.WriteTo(buf, tcpAddr)
			if err == nil {
				totalBytes += n
				continue
			}
			log.Printf("err: %v", err)
			time.Sleep(time.Second)
		}
	}

	w, err := tcp.NewTCPWrapper(linkName)
	if err != nil {
		panic(err)
	}
	defer w.Shutdown()

	conn, err := w.Listen("tcp", addr)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Local address: %s\n", conn.LocalAddr())
	for {
		select {
		case <-timer.C:
			log.Printf("client: %.2f MBytes\n", float64(totalBytes)/1024)
			totalBytes = 0
		default:
		}

		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			panic(err)
		}
		totalBytes += n
	}
}

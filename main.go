package main

import (
	"flag"
	"fmt"
	"log"
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
	var totalCount int

	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)

	flag.StringVar(&linkName, "linkname", "enp3s0", "The network link on which rebroadcast should run on.")
	flag.StringVar(&addr, "addr", "0.0.0.0", "The address connect or listen")
	flag.StringVar(&mode, "mode", "client", "The mode of operation (server or client)")
	flag.IntVar(&totalCount, "count", 10000, "The total count of packets")
	flag.Parse()

	go func() {
		http.ListenAndServe("127.0.0.1:8080", nil)
	}()

	// Remove the XDP BPF program on interrupt.
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		os.Exit(1)
	}()

	timer := time.NewTicker(time.Second)
	totalBytes := 0

	if mode == "client" {
		w, err := tcp.NewTCPWrapper(linkName)
		if err != nil {
			panic(err)
		}
		defer w.Shutdown()

		conn, err := w.Dial("tcp", addr)
		if err != nil {
			panic(err)
		}

		log.Printf("Local address: %s\n", conn.LocalAddr())
		buf := make([]byte, 1024)

		for {
			select {
			case <-timer.C:
				log.Printf("client: %.2f MBytes\n", float64(totalBytes)/1024)
				totalBytes = 0
			default:
			}

			n, _, err := conn.ReadFrom(buf)
			if err != nil {
				log.Printf("client write err: %v", err)
				continue
			}
			totalBytes += n
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
	defer conn.Close()

	conn.SetDSCP(46)
	fmt.Printf("Local address: %s\n", conn.LocalAddr())
	count := 0
	clients := conn.GetClients()
	for len(clients) == 0 {
		time.Sleep(time.Second)
		clients = conn.GetClients()
		continue
	}

	log.Printf("%d connected\n", len(clients))
	for {
		select {
		case <-timer.C:
			log.Printf("server: %.2f MBytes\n", float64(totalBytes)/1024)
			totalBytes = 0
		default:
		}

		if count >= totalCount {
			break
		}

		buf := []byte(fmt.Sprintf("Hello, %d", count))
		count++

		n, err := conn.WriteTo(buf, clients[0])
		if err != nil {
			log.Printf("server write err: %v", err)
		}
		totalBytes += n
	}
	<-c
}

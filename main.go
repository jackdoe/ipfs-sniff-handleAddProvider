// copy pasta from https://github.com/ipfs/dht-node
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/axiomhq/hyperloglog"
	human "github.com/dustin/go-humanize"
	ds "github.com/ipfs/go-datastore"
	levelds "github.com/ipfs/go-ds-leveldb"
	ipns "github.com/ipfs/go-ipns"
	logging "github.com/ipfs/go-log"
	logwriter "github.com/ipfs/go-log/writer"
	libp2p "github.com/libp2p/go-libp2p"
	circuit "github.com/libp2p/go-libp2p-circuit"
	connmgr "github.com/libp2p/go-libp2p-connmgr"
	crypto "github.com/libp2p/go-libp2p-core/crypto"
	network "github.com/libp2p/go-libp2p-core/network"
	host "github.com/libp2p/go-libp2p-host"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	dhtmetrics "github.com/libp2p/go-libp2p-kad-dht/metrics"
	dhtopts "github.com/libp2p/go-libp2p-kad-dht/opts"
	pstore "github.com/libp2p/go-libp2p-peerstore"
	record "github.com/libp2p/go-libp2p-record"
	secio "github.com/libp2p/go-libp2p-secio"
	id "github.com/libp2p/go-libp2p/p2p/protocol/identify"
	ma "github.com/multiformats/go-multiaddr"
)

var _ = dhtmetrics.DefaultViews
var _ = circuit.P_CIRCUIT
var _ = logwriter.WriterGroup

var (
	log = logging.Logger("dhtbooster")
)

type Event struct {
	Event  string
	System string
	Time   string
}

type provInfo struct {
	Key      string
	Duration time.Duration
}

//func init() { logging.SetDebugLogging() }

func waitForNotifications(r io.Reader, provs chan *provInfo) {
	var e map[string]interface{}
	dec := json.NewDecoder(r)
	for {
		err := dec.Decode(&e)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[waitForNotifications error: %s]\n", err)
			close(provs)
			return
		}

		event := e["Operation"]
		if event == "handleAddProvider" {
			provs <- &provInfo{
				Key:      (e["Tags"].(map[string]interface{}))["key"].(string),
				Duration: time.Duration(e["Duration"].(float64)),
			}
		}
	}
}

var bootstrappers = []string{
	"/ip4/104.131.131.82/tcp/4001/ipfs/QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ",  // mars.i.ipfs.io
	"/ip4/104.236.176.52/tcp/4001/ipfs/QmSoLnSGccFuZQJzRadHn95W2CrSFmZuTdDWP8HXaHca9z",  // neptune (to be neptune.i.ipfs.io)
	"/ip4/104.236.179.241/tcp/4001/ipfs/QmSoLpPVmHKQ4XTPdz8tjDFgdeRFkpV8JgYq8JVJ69RrZm", // pluto (to be pluto.i.ipfs.io)
	"/ip4/162.243.248.213/tcp/4001/ipfs/QmSoLueR4xBeUbY9WZ9xGUUxunbKWcrNFTDAadQJmocnWm", // uranus (to be uranus.i.ipfs.io)
	"/ip4/128.199.219.111/tcp/4001/ipfs/QmSoLSafTMBsPKadTEgaXctDQVcqN88CNLHXMkTNwMKPnu", // saturn (to be saturn.i.ipfs.io)
	"/ip4/104.236.76.40/tcp/4001/ipfs/QmSoLV4Bbm51jM9C4gDYZQ9Cy3U6aXMJDAbzgu2fzaDs64",   // venus (to be venus.i.ipfs.io)
	"/ip4/178.62.158.247/tcp/4001/ipfs/QmSoLer265NRgSp2LA3dPaeykiS1J6DifTC88f5uVQKNAd",  // earth (to be earth.i.ipfs.io)
	"/ip4/178.62.61.185/tcp/4001/ipfs/QmSoLMeWqB7YGVLJN3pNLQpmmEk35v6wYtsMGLzSr5QBU3",   // mercury (to be mercury.i.ipfs.io)
	"/ip4/104.236.151.122/tcp/4001/ipfs/QmSoLju6m7xTh3DuokvT3886QRYqxAzb1kShaanJgW36yx", // jupiter (to be jupiter.i.ipfs.io)
}

func bootstrapper() pstore.PeerInfo {
	bsa := bootstrappers[rand.Intn(len(bootstrappers))]

	a, err := ma.NewMultiaddr(bsa)
	if err != nil {
		panic(err)
	}

	ai, err := pstore.InfoFromP2pAddr(a)
	if err != nil {
		panic(err)
	}

	return *ai
}

func makeAndStartNode(ds ds.Batching, addr string, limiter chan struct{}) (host.Host, *dht.IpfsDHT, error) {
	cmgr := connmgr.NewConnManager(1500, 2000, time.Minute)

	priv, _, err := crypto.GenerateKeyPair(crypto.RSA, 2048)
	if err != nil {
		return nil, nil, err
	}

	security := libp2p.Security(secio.ID, func() (*secio.Transport, error) {
		x, _, err := crypto.GenerateKeyPair(crypto.RSA, 2048)
		if err != nil {
			panic(err)
		}
		return secio.New(x)
	})
	opts := []libp2p.Option{libp2p.ListenAddrStrings(addr), libp2p.ConnectionManager(cmgr), libp2p.Identity(priv), security}

	h, err := libp2p.New(context.Background(), opts...)
	if err != nil {
		panic(err)
	}

	d, err := dht.New(context.Background(), h, dhtopts.Datastore(ds))
	if err != nil {
		panic(err)
	}

	d.Validator = record.NamespacedValidator{
		"pk":   record.PublicKeyValidator{},
		"ipns": ipns.Validator{KeyBook: h.Peerstore()},
	}

	go func() {
		if limiter != nil {
			limiter <- struct{}{}
		}

		for i := 0; i < 2; i++ {
			b := bootstrapper()
			if err := h.Connect(context.Background(), b); err != nil {
				fmt.Fprintf(os.Stderr, "[BOOTSTARP connect failed: %s]\n", err.Error())
				i--
			} else {
				fmt.Fprintf(os.Stderr, "[BOOTSTRAP SUCCESS: %s]\n", b)
			}
		}

		time.Sleep(time.Second)

		timeout := time.Minute * 5
		tctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		d.BootstrapOnce(tctx, dht.BootstrapConfig{Queries: 4, Timeout: timeout})

		if limiter != nil {
			<-limiter
		}
	}()
	return h, d, nil
}

func main() {
	many := flag.Int("many", 1, "Instead of running one dht, run many!")
	portBegin := flag.Int("port-begin", 0, "If set, begin port allocation here")
	listen := flag.String("listen", "0.0.0.0", "listen addr")
	bootstrapConcurency := flag.Int("bootstrapConc", 1, "How many concurrent bootstraps to run")
	stagger := flag.Duration("stagger", 0*time.Second, "Duration to stagger nodes starts by")
	flag.Parse()
	id.ClientVersion = "dhtbooster/2"

	runMany(*portBegin, *many, *bootstrapConcurency, *listen, *stagger)
}

func runMany(portBegin, many, bsCon int, listen string, stagger time.Duration) {
	ds, err := levelds.NewDatastore("", nil)
	if err != nil {
		panic(err)
	}

	start := time.Now()
	var hosts []host.Host
	var dhts []*dht.IpfsDHT

	var hyperLock sync.Mutex
	hyperlog := hyperloglog.New()
	var peersConnected int64

	notifiee := &network.NotifyBundle{
		ConnectedF: func(_ network.Network, v network.Conn) {
			hyperLock.Lock()
			hyperlog.Insert([]byte(v.RemotePeer()))
			hyperLock.Unlock()

			atomic.AddInt64(&peersConnected, 1)
		},
		DisconnectedF: func(_ network.Network, v network.Conn) {
			atomic.AddInt64(&peersConnected, -1)
		},
	}

	limiter := make(chan struct{}, bsCon)
	for i := 0; i < many; i++ {
		time.Sleep(stagger)
		port := 0
		if portBegin > 0 {
			port = portBegin
			portBegin++
		}
		laddr := fmt.Sprintf("/ip4/%s/tcp/%d", listen, port)
		h, d, err := makeAndStartNode(ds, laddr, limiter)
		if err != nil {
			panic(err)
		}
		h.Network().Notify(notifiee)
		hosts = append(hosts, h)
		dhts = append(dhts, d)
	}

	provs := make(chan *provInfo, 16)
	r, w := io.Pipe()
	logwriter.WriterGroup.AddWriter(w)
	go waitForNotifications(r, provs)

	totalprovs := 0
	reportInterval := time.NewTicker(time.Second * 5)
	for {
		select {
		case p, ok := <-provs:
			if !ok {
				totalprovs = -1
				provs = nil
			} else {
				if p.Key != "" {
					fmt.Printf("KEY:%v\n", p.Key)
				}
				totalprovs++
			}
		case <-reportInterval.C:
			hyperLock.Lock()
			uniqpeers := hyperlog.Estimate()
			hyperLock.Unlock()
			printStatusLine(many, start, atomic.LoadInt64(&peersConnected), uniqpeers, totalprovs)
		}
	}
}

func printStatusLine(ndht int, start time.Time, totalpeers int64, uniqpeers uint64, totalprovs int) {
	uptime := time.Second * time.Duration(int(time.Since(start).Seconds()))
	var mstat runtime.MemStats
	runtime.ReadMemStats(&mstat)

	fmt.Fprintf(os.Stderr, "[NumDhts: %d, Uptime: %s, Memory Usage: %s, TotalPeers: %d/%d, Total Provs: %d]\n", ndht, uptime, human.Bytes(mstat.Alloc), totalpeers, uniqpeers, totalprovs)
}

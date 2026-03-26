package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xtaci/smux"
)

var (
	flagRole  = flag.String("role", "", "server or client")
	flagEmail = flag.String("email", "", "rendezvous account email")
	flagPass  = flag.String("pass", "", "rendezvous account password")
	flagAddr  = flag.String("addr", "", "server: upstream host:port, client: listen host:port")
	flagPoll  = flag.Duration("poll", 100*time.Millisecond, "polling interval")
	flagChunk = flag.Int("chunk", 70000, "max chunk size in bytes")
	flagBuf   = flag.Int("buf", 16, "tunnel channel buffer size")
	flagSlots = flag.Int("slots", 4, "number of parallel note slots")
	flagDebug = flag.Bool("debug", false, "enable debug logging")
)

var baseURL string // set via -ldflags "-X main.baseURL=..."

var (
	textareaRe = regexp.MustCompile(`<textarea[^>]*>([\s\S]*?)</textarea>`)
	httpClient = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
)

// --- note client ---

type client struct{ email, password string }

func (c *client) register() error {
	resp, err := post("sign2.php", url.Values{"email": {c.email}, "password": {c.password}, "password2": {c.password}, "submit": {"submit"}})
	if err != nil {
		return err
	}
	if strings.Contains(resp, "موفقیت") || strings.Contains(resp, "قبلا") {
		return nil
	}
	return fmt.Errorf("register failed")
}

func (c *client) read() (string, error) {
	resp, err := post("panel.php", url.Values{"email": {c.email}, "password": {c.password}, "submit": {"submit"}})
	if err != nil {
		return "", err
	}
	if strings.Contains(resp, "نادرست") {
		return "", fmt.Errorf("bad credentials")
	}
	m := textareaRe.FindStringSubmatch(resp)
	if m == nil {
		return "", fmt.Errorf("no content")
	}
	return m[1], nil
}

func (c *client) write(content string) error {
	resp, err := post("save.php", url.Values{"txt": {content}, "huser": {b64(c.email)}, "hpass": {b64(c.password)}, "save": {"save"}})
	if err != nil {
		return err
	}
	if strings.Contains(resp, "ذخيره شد") {
		return nil
	}
	return fmt.Errorf("save failed")
}

func post(path string, data url.Values) (string, error) {
	resp, err := httpClient.PostForm(baseURL+"/"+path, data)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// --- account pool ---

type accountPool struct {
	seed []byte
}

func newAccountPool(email, pass string) *accountPool {
	h := sha256.Sum256([]byte(email + ":" + pass))
	return &accountPool{seed: h[:]}
}

func (p *accountPool) derive(slot int) (emailA, passA, emailB, passB string) {
	d := func(label string) string {
		mac := hmac.New(sha256.New, p.seed)
		mac.Write([]byte(fmt.Sprintf("%s-%d", label, slot)))
		return hex.EncodeToString(mac.Sum(nil))
	}
	emailA = fmt.Sprintf("tun-%s@t.io", d("ae")[:16])
	passA = d("ap")[:32]
	emailB = fmt.Sprintf("tun-%s@t.io", d("be")[:16])
	passB = d("bp")[:32]
	return
}

// --- rendezvous ---

func split(s string, size int) []string {
	if len(s) == 0 {
		return []string{""}
	}
	var out []string
	for len(s) > 0 {
		end := size
		if end > len(s) {
			end = len(s)
		}
		out = append(out, s[:end])
		s = s[end:]
	}
	return out
}

func parseChunk(raw string) (int, int, string) {
	nl := strings.IndexByte(raw, '\n')
	if nl < 0 {
		return 0, 0, raw
	}
	slash := strings.IndexByte(raw[:nl], '/')
	if slash < 0 {
		return 0, 0, raw
	}
	i, _ := strconv.Atoi(raw[:slash])
	n, _ := strconv.Atoi(raw[slash+1 : nl])
	return i, n, raw[nl+1:]
}

// --- slot tunnel (N parallel note pairs) ---

type slotTunnel struct {
	slots     int
	sendSlots []*client // N send note accounts
	recvSlots []*client // N recv note accounts
	Inbox     chan []byte
	Outbox    chan []byte
	poll      time.Duration
	chunk     int
}

func newSlotTunnel(slots int, sendSlots, recvSlots []*client) *slotTunnel {
	return &slotTunnel{
		slots:     slots,
		sendSlots: sendSlots,
		recvSlots: recvSlots,
		Inbox:     make(chan []byte, *flagBuf*slots),
		Outbox:    make(chan []byte, *flagBuf*slots),
		poll:      *flagPoll,
		chunk:     *flagChunk,
	}
}

func (st *slotTunnel) run(ctx context.Context) {
	// Dispatch outbox messages to slot channels round-robin
	slotChans := make([]chan seqMsg, st.slots)
	for i := range slotChans {
		slotChans[i] = make(chan seqMsg, *flagBuf)
	}

	// Dispatcher: assigns seq numbers and round-robins to slots
	go func() {
		var seq uint64
		for {
			select {
			case <-ctx.Done():
				return
			case data := <-st.Outbox:
				encoded := base64.StdEncoding.EncodeToString(data)
				chunks := split(encoded, st.chunk)
				for ci, chunk := range chunks {
					msg := seqMsg{
						seq:  seq,
						data: fmt.Sprintf("%d|%d/%d\n%s", seq, ci+1, len(chunks), chunk),
					}
					slot := int(seq) % st.slots
					select {
					case slotChans[slot] <- msg:
					case <-ctx.Done():
						return
					}
					seq++
				}
			}
		}
	}()

	// N parallel senders
	for i := 0; i < st.slots; i++ {
		go st.slotSender(ctx, i, slotChans[i])
	}

	// N parallel receivers feed into a shared raw channel
	rawCh := make(chan seqMsg, *flagBuf*st.slots)
	for i := 0; i < st.slots; i++ {
		go st.slotReceiver(ctx, i, rawCh)
	}

	// Reorder goroutine: delivers to Inbox in seq order
	go st.reorder(ctx, rawCh)
}

type seqMsg struct {
	seq  uint64
	data string
}

func (st *slotTunnel) slotSender(ctx context.Context, slot int, ch chan seqMsg) {
	c := st.sendSlots[slot]
	for {
		select {
		case <-ctx.Done():
			return
		case msg := <-ch:
			// Write and wait for ACK
			for c.write(msg.data) != nil {
				time.Sleep(st.poll)
			}
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}
				content, err := c.read()
				if err == nil && strings.TrimSpace(content) == "" {
					break
				}
				time.Sleep(st.poll)
			}
		}
	}
}

func (st *slotTunnel) slotReceiver(ctx context.Context, slot int, rawCh chan seqMsg) {
	c := st.recvSlots[slot]
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		content, err := c.read()
		if err != nil {
			time.Sleep(st.poll)
			continue
		}
		content = strings.TrimSpace(content)
		if content == "" {
			time.Sleep(st.poll)
			continue
		}
		// ACK: clear the note
		for c.write("") != nil {
			time.Sleep(st.poll)
		}
		// Parse seq from "seq|chunk_header\ndata"
		pipe := strings.IndexByte(content, '|')
		if pipe < 0 {
			continue
		}
		seq, err := strconv.ParseUint(content[:pipe], 10, 64)
		if err != nil {
			continue
		}
		select {
		case rawCh <- seqMsg{seq: seq, data: content[pipe+1:]}:
		case <-ctx.Done():
			return
		}
	}
}

func (st *slotTunnel) reorder(ctx context.Context, rawCh chan seqMsg) {
	var nextSeq uint64
	pending := make(map[uint64]string)
	// Reassembly state
	var parts []string
	var totalParts int

	for {
		select {
		case <-ctx.Done():
			return
		case msg := <-rawCh:
			pending[msg.seq] = msg.data

			for {
				data, ok := pending[nextSeq]
				if !ok {
					break
				}
				delete(pending, nextSeq)
				nextSeq++

				// Parse chunk header: "i/total\ndata"
				i, n, body := parseChunk(data)
				if i <= 0 {
					// Single chunk, decode directly
					decoded, err := base64.StdEncoding.DecodeString(data)
					if err != nil {
						continue
					}
					select {
					case st.Inbox <- decoded:
					case <-ctx.Done():
						return
					}
					continue
				}

				if i == 1 {
					parts = make([]string, 0, n)
					totalParts = n
				}
				if n != totalParts || i != len(parts)+1 {
					slog.Warn("reorder chunk mismatch, resetting", "i", i, "expected", len(parts)+1)
					parts, totalParts = nil, 0
					continue
				}
				parts = append(parts, body)
				if len(parts) == totalParts {
					decoded, err := base64.StdEncoding.DecodeString(strings.Join(parts, ""))
					if err != nil {
						parts, totalParts = nil, 0
						continue
					}
					select {
					case st.Inbox <- decoded:
					case <-ctx.Done():
						return
					}
					parts, totalParts = nil, 0
				}
			}
		}
	}
}

// --- tunnelConn: adapts slotTunnel to io.ReadWriteCloser for smux ---

type tunnelConn struct {
	st     *slotTunnel
	rbuf   bytes.Buffer
	ctx    context.Context
	cancel context.CancelFunc
}

func newTunnelConn(ctx context.Context, st *slotTunnel) *tunnelConn {
	ctx, cancel := context.WithCancel(ctx)
	return &tunnelConn{st: st, ctx: ctx, cancel: cancel}
}

func (tc *tunnelConn) Read(p []byte) (int, error) {
	if tc.rbuf.Len() > 0 {
		return tc.rbuf.Read(p)
	}
	select {
	case data, ok := <-tc.st.Inbox:
		if !ok {
			return 0, io.EOF
		}
		tc.rbuf.Write(data)
		return tc.rbuf.Read(p)
	case <-tc.ctx.Done():
		return 0, io.EOF
	}
}

func (tc *tunnelConn) Write(p []byte) (int, error) {
	buf := make([]byte, len(p))
	copy(buf, p)
	select {
	case tc.st.Outbox <- buf:
		return len(p), nil
	case <-tc.ctx.Done():
		return 0, io.ErrClosedPipe
	}
}

func (tc *tunnelConn) Close() error {
	tc.cancel()
	return nil
}

// --- relay: smux stream ↔ TCP conn ---

func relay(stream *smux.Stream, conn net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		defer func() { done <- struct{}{} }()
		io.Copy(conn, stream)
	}()
	go func() {
		defer func() { done <- struct{}{} }()
		io.Copy(stream, conn)
	}()
	<-done
}

// --- server/client setup ---

func registerSlotAccounts(pool *accountPool, slots int) ([]*client, []*client) {
	sendSlots := make([]*client, slots)
	recvSlots := make([]*client, slots)

	var wg sync.WaitGroup
	for i := 0; i < slots; i++ {
		wg.Add(1)
		go func(slot int) {
			defer wg.Done()
			eA, pA, eB, pB := pool.derive(slot)
			a := &client{eA, pA}
			b := &client{eB, pB}
			a.register()
			b.register()
			a.write("")
			b.write("")
			// Server sends on B, recvs on A
			sendSlots[slot] = b
			recvSlots[slot] = a
		}(i)
	}
	wg.Wait()
	return sendSlots, recvSlots
}

func deriveSlotClients(pool *accountPool, slots int) ([]*client, []*client) {
	sendSlots := make([]*client, slots)
	recvSlots := make([]*client, slots)
	for i := 0; i < slots; i++ {
		eA, pA, eB, pB := pool.derive(i)
		// Client sends on A, recvs on B
		sendSlots[i] = &client{eA, pA}
		recvSlots[i] = &client{eB, pB}
	}
	return sendSlots, recvSlots
}

func publishRendezvous(rv *client) error {
	slog.Info("registering rendezvous account")
	rv.register()
	if err := rv.write("ready"); err != nil {
		return err
	}
	slog.Info("rendezvous published, waiting for client")
	return nil
}

func waitRendezvous(rv *client) error {
	slog.Info("waiting for rendezvous")
	for {
		content, err := rv.read()
		if err != nil {
			time.Sleep(time.Second)
			continue
		}
		if strings.TrimSpace(content) != "" {
			break
		}
		time.Sleep(*flagPoll)
	}
	slog.Info("rendezvous received")
	return nil
}

// --- main ---

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: note-tunnel -role <server|client> -email <email> -pass <pass> -addr <host:port>\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	level := slog.LevelInfo
	if *flagDebug {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))

	if *flagRole == "" || *flagEmail == "" || *flagPass == "" || *flagAddr == "" {
		flag.Usage()
		os.Exit(1)
	}
	role, addr := *flagRole, *flagAddr
	ctx := context.Background()
	rv := &client{*flagEmail, *flagPass}
	pool := newAccountPool(*flagEmail, *flagPass)
	slots := *flagSlots

	slog.Info("starting", "role", role, "addr", addr, "slots", slots)

	// Rendezvous: server publishes, client reads — just a handshake
	if role == "server" {
		if err := publishRendezvous(rv); err != nil {
			slog.Error("rendezvous failed", "err", err)
			os.Exit(1)
		}
	} else {
		if err := waitRendezvous(rv); err != nil {
			slog.Error("rendezvous failed", "err", err)
			os.Exit(1)
		}
	}

	// Register/derive slot accounts
	slog.Info("setting up slot accounts", "slots", slots)
	var sendSlots, recvSlots []*client
	if role == "server" {
		sendSlots, recvSlots = registerSlotAccounts(pool, slots)
	} else {
		sendSlots, recvSlots = deriveSlotClients(pool, slots)
	}
	slog.Info("slot accounts ready")

	// Create slot tunnel
	st := newSlotTunnel(slots, sendSlots, recvSlots)
	st.run(ctx)

	// Wrap in tunnelConn for smux
	tc := newTunnelConn(ctx, st)

	if role == "server" {
		sess, err := smux.Server(tc, nil)
		if err != nil {
			slog.Error("smux server failed", "err", err)
			os.Exit(1)
		}
		slog.Info("tunnel ready, waiting for streams", "upstream", addr)
		for {
			stream, err := sess.AcceptStream()
			if err != nil {
				slog.Error("accept stream failed", "err", err)
				return
			}
			slog.Debug("stream accepted", "id", stream.ID())
			go func() {
				defer stream.Close()
				conn, err := net.Dial("tcp", addr)
				if err != nil {
					slog.Error("dial upstream failed", "err", err)
					return
				}
				defer conn.Close()
				slog.Info("stream opened", "id", stream.ID(), "upstream", addr)
				relay(stream, conn)
				slog.Info("stream closed", "id", stream.ID())
			}()
		}
	} else {
		sess, err := smux.Client(tc, nil)
		if err != nil {
			slog.Error("smux client failed", "err", err)
			os.Exit(1)
		}
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			slog.Error("listen failed", "addr", addr, "err", err)
			os.Exit(1)
		}
		slog.Info("listening", "addr", addr)
		for {
			conn, err := ln.Accept()
			if err != nil {
				slog.Error("accept failed", "err", err)
				continue
			}
			go func() {
				defer conn.Close()
				stream, err := sess.OpenStream()
				if err != nil {
					slog.Error("open stream failed", "err", err)
					return
				}
				defer stream.Close()
				slog.Debug("stream opened", "id", stream.ID(), "remote", conn.RemoteAddr())
				relay(stream, conn)
				slog.Debug("stream closed", "id", stream.ID())
			}()
		}
	}
}

package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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
)

var (
	flagRole  = flag.String("role", "", "server or client")
	flagEmail = flag.String("email", "", "rendezvous account email")
	flagPass  = flag.String("pass", "", "rendezvous account password")
	flagAddr  = flag.String("addr", "", "server: upstream host:port, client: listen host:port")
	flagPoll  = flag.Duration("poll", 100*time.Millisecond, "polling interval")
	flagChunk = flag.Int("chunk", 70000, "max chunk size in bytes")
	flagBuf   = flag.Int("buf", 16, "tunnel channel buffer size")
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

// --- tunnel ---

type tunnel struct {
	send, recv     *client
	Inbox, Outbox  chan string
	poll           time.Duration
	chunk          int
}

type rendezvousInfo struct {
	AE string `json:"ae"`
	AP string `json:"ap"`
	BE string `json:"be"`
	BP string `json:"bp"`
}

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func randAccount() (string, string) {
	return fmt.Sprintf("tun-%s@t.io", randHex(8)), randHex(16)
}

func startServer(ctx context.Context, rv *client) (*tunnel, error) {
	slog.Info("registering rendezvous account")
	rv.register()
	ae, ap := randAccount()
	be, bp := randAccount()
	a := &client{ae, ap}
	b := &client{be, bp}
	if err := a.register(); err != nil {
		return nil, err
	}
	if err := b.register(); err != nil {
		return nil, err
	}
	a.write("")
	b.write("")
	data, _ := json.Marshal(rendezvousInfo{ae, ap, be, bp})
	if err := rv.write(string(data)); err != nil {
		return nil, err
	}
	slog.Info("rendezvous published, waiting for client")
	t := newTunnel(b, a)
	t.run(ctx)
	return t, nil
}

func startClient(ctx context.Context, rv *client) (*tunnel, error) {
	slog.Info("waiting for rendezvous info")
	var info rendezvousInfo
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		content, err := rv.read()
		if err != nil {
			time.Sleep(time.Second)
			continue
		}
		content = strings.TrimSpace(content)
		if content == "" {
			time.Sleep(*flagPoll)
			continue
		}
		info = rendezvousInfo{}
		if err := json.Unmarshal([]byte(content), &info); err != nil || info.AE == "" {
			time.Sleep(time.Second)
			continue
		}
		break
	}
	slog.Info("rendezvous received")
	t := newTunnel(&client{info.AE, info.AP}, &client{info.BE, info.BP})
	t.run(ctx)
	return t, nil
}

func newTunnel(send, recv *client) *tunnel {
	return &tunnel{
		send: send, recv: recv,
		Inbox:  make(chan string, *flagBuf),
		Outbox: make(chan string, *flagBuf),
		poll:   *flagPoll,
		chunk:  *flagChunk,
	}
}

func (t *tunnel) run(ctx context.Context) {
	go t.sendLoop(ctx)
	go t.recvLoop(ctx)
}

func (t *tunnel) sendRaw(ctx context.Context, data string) bool {
	for t.send.write(data) != nil {
		time.Sleep(t.poll)
	}
	for {
		select {
		case <-ctx.Done():
			return false
		default:
		}
		c, err := t.send.read()
		if err == nil && strings.TrimSpace(c) == "" {
			return true
		}
		time.Sleep(t.poll)
	}
}

func (t *tunnel) recvRaw(ctx context.Context) (string, bool) {
	for {
		select {
		case <-ctx.Done():
			return "", false
		default:
		}
		content, err := t.recv.read()
		if err != nil {
			time.Sleep(t.poll)
			continue
		}
		content = strings.TrimSpace(content)
		if content == "" {
			time.Sleep(t.poll)
			continue
		}
		for t.recv.write("") != nil {
			time.Sleep(t.poll)
		}
		return content, true
	}
}

func (t *tunnel) sendLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case msg := <-t.Outbox:
			chunks := split(msg, t.chunk)
			for i, chunk := range chunks {
				if !t.sendRaw(ctx, fmt.Sprintf("%d/%d\n%s", i+1, len(chunks), chunk)) {
					return
				}
			}
		}
	}
}

func (t *tunnel) recvLoop(ctx context.Context) {
	var parts []string
	var total int
	for {
		raw, ok := t.recvRaw(ctx)
		if !ok {
			return
		}
		i, n, body := parseChunk(raw)
		if i <= 0 {
			select {
			case t.Inbox <- raw:
			case <-ctx.Done():
				return
			}
			continue
		}
		if i == 1 {
			parts = make([]string, 0, n)
			total = n
		}
		if n != total || i != len(parts)+1 {
			slog.Warn("recvLoop chunk out of order, resetting", "i", i, "expected", len(parts)+1)
			parts, total = nil, 0
			continue
		}
		parts = append(parts, body)
		if len(parts) == total {
			select {
			case t.Inbox <- strings.Join(parts, ""):
			case <-ctx.Done():
				return
			}
			parts, total = nil, 0
		}
	}
}

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

// --- control protocol ---

type controlMsg struct {
	Type string `json:"type"`
	SID  string `json:"sid"`
	SE   string `json:"se,omitempty"`
	SP   string `json:"sp,omitempty"`
	RE   string `json:"re,omitempty"`
	RP   string `json:"rp,omitempty"`
}

// --- mux ---

type streamInfo struct {
	tun    *tunnel
	cancel context.CancelFunc
}

type mux struct {
	ctrl    *tunnel
	streams map[string]*streamInfo
	pending map[string]chan controlMsg
	mu      sync.Mutex
	ctx     context.Context
}

func newMux(ctx context.Context, ctrl *tunnel) *mux {
	return &mux{
		ctrl:    ctrl,
		streams: make(map[string]*streamInfo),
		pending: make(map[string]chan controlMsg),
		ctx:     ctx,
	}
}

func (m *mux) addStream(sid string, tun *tunnel, cancel context.CancelFunc) {
	m.mu.Lock()
	m.streams[sid] = &streamInfo{tun: tun, cancel: cancel}
	m.mu.Unlock()
}

func (m *mux) closeStream(sid string) {
	m.mu.Lock()
	si, ok := m.streams[sid]
	if ok {
		delete(m.streams, sid)
	}
	m.mu.Unlock()
	if ok {
		si.cancel()
	}
}

func (m *mux) sendControl(msg controlMsg) {
	data, _ := json.Marshal(msg)
	m.ctrl.Outbox <- string(data)
}

// --- server ---

func (m *mux) serverLoop(upstreamAddr string) {
	slog.Info("tunnel ready", "upstream", upstreamAddr)
	for {
		select {
		case <-m.ctx.Done():
			return
		case raw := <-m.ctrl.Inbox:
			var msg controlMsg
			if json.Unmarshal([]byte(raw), &msg) != nil {
				continue
			}
			switch msg.Type {
			case "open":
				go m.serverOpenStream(msg.SID, upstreamAddr)
			case "close":
				slog.Info("stream closed", "sid", msg.SID, "by", "client")
				m.closeStream(msg.SID)
			}
		}
	}
}

func (m *mux) serverOpenStream(sid, upstreamAddr string) {
	slog.Debug("opening stream", "sid", sid)

	ae, ap := randAccount()
	be, bp := randAccount()
	a := &client{ae, ap}
	b := &client{be, bp}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); a.register(); a.write("") }()
	go func() { defer wg.Done(); b.register(); b.write("") }()
	wg.Wait()

	m.sendControl(controlMsg{Type: "opened", SID: sid, SE: ae, SP: ap, RE: be, RP: bp})

	sctx, cancel := context.WithCancel(m.ctx)
	// server sends on b, recvs on a
	tun := newTunnel(b, a)
	tun.run(sctx)
	m.addStream(sid, tun, cancel)

	conn, err := net.Dial("tcp", upstreamAddr)
	if err != nil {
		slog.Error("dial upstream failed", "sid", sid, "err", err)
		m.closeStream(sid)
		m.sendControl(controlMsg{Type: "close", SID: sid})
		return
	}
	slog.Info("stream opened", "sid", sid, "upstream", upstreamAddr)
	tunnelRelay(sctx, tun, conn)
	conn.Close()
	slog.Info("stream closed", "sid", sid)
	m.closeStream(sid)
	m.sendControl(controlMsg{Type: "close", SID: sid})
}

// --- client ---

func (m *mux) clientLoop() {
	for {
		select {
		case <-m.ctx.Done():
			return
		case raw := <-m.ctrl.Inbox:
			var msg controlMsg
			if json.Unmarshal([]byte(raw), &msg) != nil {
				continue
			}
			switch msg.Type {
			case "opened":
				m.mu.Lock()
				ch, ok := m.pending[msg.SID]
				if ok {
					delete(m.pending, msg.SID)
				}
				m.mu.Unlock()
				if ok {
					ch <- msg
				}
			case "close":
				slog.Info("stream closed", "sid", msg.SID, "by", "server")
				m.closeStream(msg.SID)
			}
		}
	}
}

func (m *mux) clientOpenStream(conn net.Conn) {
	remote := conn.RemoteAddr().String()
	sid := randHex(8)
	slog.Debug("opening stream", "sid", sid, "remote", remote)

	ch := make(chan controlMsg, 1)
	m.mu.Lock()
	m.pending[sid] = ch
	m.mu.Unlock()

	m.sendControl(controlMsg{Type: "open", SID: sid})

	var reply controlMsg
	select {
	case reply = <-ch:
	case <-time.After(30 * time.Second):
		slog.Error("stream open timeout", "sid", sid)
		m.mu.Lock()
		delete(m.pending, sid)
		m.mu.Unlock()
		conn.Close()
		return
	}

	sctx, cancel := context.WithCancel(m.ctx)
	// client sends on a (SE/SP), recvs on b (RE/RP)
	tun := newTunnel(&client{reply.SE, reply.SP}, &client{reply.RE, reply.RP})
	tun.run(sctx)
	m.addStream(sid, tun, cancel)

	slog.Info("stream opened", "sid", sid, "remote", remote)
	tunnelRelay(sctx, tun, conn)
	conn.Close()
	slog.Info("stream closed", "sid", sid, "remote", remote)
	m.closeStream(sid)
	m.sendControl(controlMsg{Type: "close", SID: sid})
}

// --- tunnel relay ---

func tunnelRelay(ctx context.Context, tun *tunnel, conn net.Conn) {
	done := make(chan struct{}, 2)

	// TCP → tunnel
	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 32*1024)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				select {
				case tun.Outbox <- base64.StdEncoding.EncodeToString(buf[:n]):
				case <-ctx.Done():
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	// tunnel → TCP
	go func() {
		defer func() { done <- struct{}{} }()
		for {
			select {
			case msg, ok := <-tun.Inbox:
				if !ok {
					return
				}
				data, err := base64.StdEncoding.DecodeString(msg)
				if err != nil {
					continue
				}
				conn.Write(data)
			case <-ctx.Done():
				return
			}
		}
	}()

	<-done
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

	slog.Info("starting", "role", role, "addr", addr)

	var ctrl *tunnel
	var err error
	if role == "server" {
		ctrl, err = startServer(ctx, rv)
	} else {
		ctrl, err = startClient(ctx, rv)
	}
	if err != nil {
		slog.Error("tunnel setup failed", "err", err)
		os.Exit(1)
	}

	m := newMux(ctx, ctrl)

	if role == "server" {
		m.serverLoop(addr)
	} else {
		go m.clientLoop()
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
			go m.clientOpenStream(conn)
		}
	}
}

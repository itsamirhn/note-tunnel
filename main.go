package main

import (
	"bytes"
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
	flagDebug = flag.Bool("debug", false, "enable debug logging")
)

var baseURL string // set via -ldflags "-X main.baseURL=..."

var (
	capisRe    = regexp.MustCompile(`name=capis\s+value=(\d+)`)
	textareaRe = regexp.MustCompile(`<textarea[^>]*>([\s\S]*?)</textarea>`)
	httpClient = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
)

// --- note client ---

type client struct{ email, password string }

func (c *client) register() error {
	slog.Debug("registering account", "email", c.email)
	cap, err := getCaptcha("sign.php")
	if err != nil {
		return err
	}
	resp, err := post("sign2.php", url.Values{"email": {c.email}, "password": {c.password}, "password2": {c.password}, "capis": {cap}, "cap": {cap}, "submit": {"submit"}})
	if err != nil {
		return err
	}
	if strings.Contains(resp, "موفقیت") || strings.Contains(resp, "قبلا") {
		slog.Debug("register ok", "email", c.email)
		return nil
	}
	return fmt.Errorf("register failed")
}

func (c *client) read() (string, error) {
	slog.Debug("reading note", "email", c.email)
	cap, err := getCaptcha("web.php")
	if err != nil {
		return "", err
	}
	resp, err := post("panel.php", url.Values{"email": {c.email}, "password": {c.password}, "capis": {cap}, "cap": {cap}, "submit": {"submit"}})
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
	slog.Debug("read note", "email", c.email, "len", len(m[1]))
	return m[1], nil
}

func (c *client) write(content string) error {
	slog.Debug("writing note", "email", c.email, "len", len(content))
	resp, err := post("save.php", url.Values{"txt": {content}, "huser": {b64(c.email)}, "hpass": {b64(c.password)}, "save": {"save"}})
	if err != nil {
		return err
	}
	if strings.Contains(resp, "ذخيره شد") {
		slog.Debug("write ok", "email", c.email)
		return nil
	}
	return fmt.Errorf("save failed")
}

func getCaptcha(page string) (string, error) {
	slog.Debug("fetching captcha", "page", page)
	resp, err := httpClient.Get(baseURL + "/" + page)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	m := capisRe.FindSubmatch(body)
	if m == nil {
		return "", fmt.Errorf("no captcha")
	}
	slog.Debug("captcha solved", "page", page, "value", string(m[1]))
	return string(m[1]), nil
}

func post(path string, data url.Values) (string, error) {
	slog.Debug("POST", "path", path)
	resp, err := httpClient.PostForm(baseURL+"/"+path, data)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	slog.Debug("POST response", "path", path, "status", resp.StatusCode, "len", len(body))
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
	slog.Debug("created tunnel accounts", "send", be, "recv", ae)
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
	slog.Debug("publishing rendezvous info")
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
			slog.Debug("rendezvous read error", "err", err)
			time.Sleep(time.Second)
			continue
		}
		content = strings.TrimSpace(content)
		if content == "" {
			slog.Debug("rendezvous empty, retrying")
			time.Sleep(*flagPoll)
			continue
		}
		info = rendezvousInfo{}
		if err := json.Unmarshal([]byte(content), &info); err != nil || info.AE == "" {
			slog.Debug("rendezvous bad data, retrying", "err", err)
			time.Sleep(time.Second)
			continue
		}
		break
	}
	slog.Info("rendezvous received")
	slog.Debug("tunnel accounts", "send", info.AE, "recv", info.BE)
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
	slog.Debug("sendRaw", "len", len(data))
	for t.send.write(data) != nil {
		slog.Debug("sendRaw write retry")
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
			slog.Debug("sendRaw acked")
			return true
		}
		slog.Debug("sendRaw waiting for ack")
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
			slog.Debug("recvRaw read error", "err", err)
			time.Sleep(t.poll)
			continue
		}
		content = strings.TrimSpace(content)
		if content == "" {
			time.Sleep(t.poll)
			continue
		}
		slog.Debug("recvRaw got data", "len", len(content))
		for t.recv.write("") != nil {
			slog.Debug("recvRaw ack retry")
			time.Sleep(t.poll)
		}
		slog.Debug("recvRaw acked")
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
			slog.Debug("sendLoop", "chunks", len(chunks), "len", len(msg))
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
			slog.Debug("recvLoop unchunked message", "len", len(raw))
			select {
			case t.Inbox <- raw:
			case <-ctx.Done():
				return
			}
			continue
		}
		slog.Debug("recvLoop chunk", "i", i, "n", n, "len", len(body))
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
			msg := strings.Join(parts, "")
			slog.Debug("recvLoop assembled message", "chunks", total, "len", len(msg))
			select {
			case t.Inbox <- msg:
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

// --- tunnel conn adapter ---

type tunnelConn struct {
	tun    *tunnel
	rbuf   bytes.Buffer
	closed chan struct{}
}

func newTunnelConn(t *tunnel) *tunnelConn {
	return &tunnelConn{tun: t, closed: make(chan struct{})}
}

func (tc *tunnelConn) Read(p []byte) (int, error) {
	if tc.rbuf.Len() > 0 {
		return tc.rbuf.Read(p)
	}
	select {
	case msg, ok := <-tc.tun.Inbox:
		if !ok {
			slog.Debug("tunnelConn read: inbox closed")
			return 0, io.EOF
		}
		data, err := base64.StdEncoding.DecodeString(msg)
		if err != nil {
			slog.Error("tunnelConn read: base64 decode failed", "err", err)
			return 0, err
		}
		slog.Debug("tunnelConn read", "bytes", len(data))
		tc.rbuf.Write(data)
		return tc.rbuf.Read(p)
	case <-tc.closed:
		return 0, io.EOF
	}
}

func (tc *tunnelConn) Write(p []byte) (int, error) {
	select {
	case <-tc.closed:
		return 0, io.ErrClosedPipe
	default:
	}
	slog.Debug("tunnelConn write", "bytes", len(p))
	tc.tun.Outbox <- base64.StdEncoding.EncodeToString(p)
	return len(p), nil
}

func (tc *tunnelConn) Close() error {
	select {
	case <-tc.closed:
	default:
		slog.Debug("tunnelConn closed")
		close(tc.closed)
	}
	return nil
}

// --- relay ---

func relay(a, b io.ReadWriteCloser) {
	done := make(chan struct{}, 1)
	cp := func(dst, src io.ReadWriteCloser) {
		io.Copy(dst, src)
		dst.Close()
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
}

// --- main ---

func smuxConfig() *smux.Config {
	cfg := smux.DefaultConfig()
	cfg.KeepAliveInterval = 10 * time.Second
	cfg.KeepAliveTimeout = 30 * time.Second
	return cfg
}

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

	var t *tunnel
	var err error
	if role == "server" {
		t, err = startServer(ctx, rv)
	} else {
		t, err = startClient(ctx, rv)
	}
	if err != nil {
		slog.Error("tunnel setup failed", "err", err)
		os.Exit(1)
	}

	tc := newTunnelConn(t)
	cfg := smuxConfig()

	if role == "server" {
		session, err := smux.Server(tc, cfg)
		if err != nil {
			slog.Error("smux server failed", "err", err)
			os.Exit(1)
		}
		slog.Info("tunnel ready", "upstream", addr)
		for {
			stream, err := session.AcceptStream()
			if err != nil {
				slog.Error("accept stream failed", "err", err)
				return
			}
			go func() {
				sid := stream.ID()
				slog.Debug("accepted stream", "stream", sid)
				conn, err := net.Dial("tcp", addr)
				if err != nil {
					slog.Error("dial upstream failed", "stream", sid, "addr", addr, "err", err)
					stream.Close()
					return
				}
				slog.Info("stream opened", "stream", sid, "upstream", addr)
				relay(stream, conn)
				slog.Info("stream closed", "stream", sid)
			}()
		}
	} else {
		session, err := smux.Client(tc, cfg)
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
				remote := conn.RemoteAddr().String()
				slog.Debug("accepted connection", "remote", remote)
				stream, err := session.OpenStream()
				if err != nil {
					slog.Error("open stream failed", "err", err)
					conn.Close()
					return
				}
				slog.Info("stream opened", "stream", stream.ID(), "remote", remote)
				relay(stream, conn)
				slog.Info("stream closed", "stream", stream.ID(), "remote", remote)
			}()
		}
	}
}

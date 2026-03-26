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
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	flagRole  = flag.String("role", "", "server or client")
	flagEmail = flag.String("email", "", "rendezvous account email")
	flagPass  = flag.String("pass", "", "rendezvous account password")
	flagAddr  = flag.String("addr", "", "server: upstream host:port, client: listen host:port")
	flagPoll  = flag.Duration("poll", 200*time.Millisecond, "polling interval")
	flagChunk = flag.Int("chunk", 70000, "max chunk size in bytes")
	flagBuf   = flag.Int("buf", 16, "tunnel channel buffer size")
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
	cap, err := getCaptcha("sign.php")
	if err != nil {
		return err
	}
	resp, err := post("sign2.php", url.Values{"email": {c.email}, "password": {c.password}, "password2": {c.password}, "capis": {cap}, "cap": {cap}, "submit": {"submit"}})
	if err != nil {
		return err
	}
	if strings.Contains(resp, "موفقیت") || strings.Contains(resp, "قبلا") {
		return nil
	}
	return fmt.Errorf("register failed")
}

func (c *client) read() (string, error) {
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

func getCaptcha(page string) (string, error) {
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
	return string(m[1]), nil
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
	t := newTunnel(b, a)
	t.run(ctx)
	return t, nil
}

func startClient(ctx context.Context, rv *client) (*tunnel, error) {
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

// --- tcp bridge ---

func bridge(conn net.Conn, t *tunnel) {
	// conn → tunnel
	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				t.Outbox <- base64.StdEncoding.EncodeToString(buf[:n])
			}
			if err != nil {
				return
			}
		}
	}()

	// tunnel → conn
	for msg := range t.Inbox {
		data, err := base64.StdEncoding.DecodeString(msg)
		if err != nil {
			continue
		}
		conn.Write(data)
	}
}

// --- main ---

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: cnote-tunnel -role <server|client> -email <email> -pass <pass> -addr <host:port>\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if *flagRole == "" || *flagEmail == "" || *flagPass == "" || *flagAddr == "" {
		flag.Usage()
		os.Exit(1)
	}
	role, addr := *flagRole, *flagAddr
	ctx := context.Background()
	rv := &client{*flagEmail, *flagPass}

	var t *tunnel
	var err error
	if role == "server" {
		t, err = startServer(ctx, rv)
	} else {
		t, err = startClient(ctx, rv)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if role == "server" {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "connected to %s\n", addr)
		bridge(conn, t)
	} else {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "listening on %s\n", addr)
		conn, err := ln.Accept()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "accepted %s\n", conn.RemoteAddr())
		ln.Close()
		bridge(conn, t)
	}
}

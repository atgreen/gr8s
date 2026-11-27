// k9s-relay serves the overview page's k9s: the files the page boots (unkernel, and the
// image holding k9s) and the tunnels k9s reaches the cluster through.
//
// k9s, in a Linux VM in a visitor's tab, talks plain HTTP to a host named "kube". The page
// carries each of the guest's TCP connections over a WebSocket to /k9s/tunnel, and here
// each tunnel is a connection to an HTTP server that passes reads to the API server with
// this Pod's ServiceAccount token. So the browser holds no credential, and nothing but
// reads reaches the cluster: RBAC limits what the account may read.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log"
	"mime"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
)

const (
	saDir       = "/var/run/secrets/kubernetes.io/serviceaccount"
	maxTunnels  = 256 // at once, from everyone
	maxPerPeer  = 16  // at once, from one address
	tunnelLife  = time.Hour
	idleTimeout = 5 * time.Minute
)

func main() {
	listen := envOr("LISTEN", ":8080")
	root := envOr("ROOT", "/srv")
	mime.AddExtensionType(".mjs", "text/javascript")
	mime.AddExtensionType(".erofs", "application/octet-stream")

	tunnels := newTunnelListener()
	api := &http.Server{Handler: readOnlyProxy(), IdleTimeout: idleTimeout}
	go func() { log.Fatal(api.Serve(tunnels)) }()

	mux := http.NewServeMux()
	mux.HandleFunc("/k9s/tunnel", tunnels.accept)
	mux.Handle("/k9s/", assets(root))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok\n")) })
	log.Printf("k9s-relay on %s, files from %s", listen, root)
	log.Fatal(http.ListenAndServe(listen, mux))
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

// assets serves the page's files with range requests (the image is read lazily), and a
// file's precompressed .gz in its place when the browser takes gzip and asks for all of it.
func assets(root string) http.Handler {
	files := http.FileServer(http.Dir(root))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := path.Clean(r.URL.Path)
		w.Header().Set("Cache-Control", "no-cache") // revalidated: Last-Modified makes that cheap
		if r.Header.Get("Range") == "" && strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			if _, err := os.Stat(root + name + ".gz"); err == nil {
				if t := mime.TypeByExtension(path.Ext(name)); t != "" {
					w.Header().Set("Content-Type", t)
				}
				w.Header().Set("Content-Encoding", "gzip")
				w.Header().Add("Vary", "Accept-Encoding")
				http.ServeFile(w, r, root+name+".gz")
				return
			}
		}
		files.ServeHTTP(w, r)
	})
}

// tunnelListener is a net.Listener whose connections are WebSocket tunnels.
type tunnelListener struct {
	conns  chan net.Conn
	mu     sync.Mutex
	total  int
	byPeer map[string]int
}

func newTunnelListener() *tunnelListener {
	return &tunnelListener{conns: make(chan net.Conn), byPeer: map[string]int{}}
}

func (l *tunnelListener) Accept() (net.Conn, error) { return <-l.conns, nil }
func (l *tunnelListener) Close() error              { return nil }
func (l *tunnelListener) Addr() net.Addr            { return &net.TCPAddr{} }

// peer is the visitor's address: the last one the Gateway added to X-Forwarded-For.
func peer(r *http.Request) string {
	if f := r.Header.Get("X-Forwarded-For"); f != "" {
		parts := strings.Split(f, ",")
		return strings.TrimSpace(parts[len(parts)-1])
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return host
}

func (l *tunnelListener) admit(who string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.total >= maxTunnels || l.byPeer[who] >= maxPerPeer {
		return false
	}
	l.total++
	l.byPeer[who]++
	return true
}

func (l *tunnelListener) release(who string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.total--
	if l.byPeer[who]--; l.byPeer[who] <= 0 {
		delete(l.byPeer, who)
	}
}

func (l *tunnelListener) accept(w http.ResponseWriter, r *http.Request) {
	who := peer(r)
	if !l.admit(who) {
		http.Error(w, "too many k9s connections; try again later", http.StatusTooManyRequests)
		return
	}
	defer l.release(who)
	c, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	c.SetReadLimit(1 << 20)
	ctx, cancel := context.WithTimeout(context.Background(), tunnelLife)
	defer cancel()
	conn := &closeNotifier{Conn: websocket.NetConn(ctx, c, websocket.MessageBinary), done: make(chan struct{})}
	select {
	case l.conns <- conn:
	case <-ctx.Done():
		return
	}
	select {
	case <-conn.done:
	case <-ctx.Done():
		conn.Close()
	}
}

// closeNotifier says when the HTTP server is done with a tunnel.
type closeNotifier struct {
	net.Conn
	once sync.Once
	done chan struct{}
}

func (c *closeNotifier) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { close(c.done) })
	return err
}

// readOnlyProxy passes reads to the API server as this Pod's ServiceAccount. It refuses
// writes, upgrades (exec, attach, port-forward) and whatever credentials a request brings.
func readOnlyProxy() http.Handler {
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	target := &url.URL{Scheme: "https", Host: net.JoinHostPort(host, port)}
	pool := x509.NewCertPool()
	if ca, err := os.ReadFile(saDir + "/ca.crt"); err == nil {
		pool.AppendCertsFromPEM(ca)
	}
	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2:   true,
		MaxIdleConnsPerHost: 32,
	}
	token := tokenReader()
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			for name := range pr.Out.Header {
				if strings.HasPrefix(strings.ToLower(name), "impersonate-") {
					pr.Out.Header.Del(name)
				}
			}
			pr.Out.Header.Del("Cookie")
			pr.Out.Header.Set("Authorization", "Bearer "+token())
		},
		Transport:     transport,
		FlushInterval: -1, // watches stream
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !readOnly(r) {
			http.Error(w, "this k9s is read-only", http.StatusForbidden)
			return
		}
		proxy.ServeHTTP(w, r)
	})
}

// readOnly allows reads, and the reviews k9s posts to learn what it may read.
func readOnly(r *http.Request) bool {
	if r.Header.Get("Upgrade") != "" {
		return false
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		return true
	case http.MethodPost:
		return strings.HasPrefix(r.URL.Path, "/apis/authorization.k8s.io/v1/selfsubject")
	}
	return false
}

// tokenReader returns the ServiceAccount token, read again each minute: the kubelet
// rotates the projected token.
func tokenReader() func() string {
	var mu sync.Mutex
	var token string
	var read time.Time
	return func() string {
		mu.Lock()
		defer mu.Unlock()
		if time.Since(read) > time.Minute {
			if b, err := os.ReadFile(saDir + "/token"); err == nil {
				token, read = strings.TrimSpace(string(b)), time.Now()
			} else if !errors.Is(err, os.ErrNotExist) || token == "" {
				log.Printf("token: %v", err)
			}
		}
		return token
	}
}

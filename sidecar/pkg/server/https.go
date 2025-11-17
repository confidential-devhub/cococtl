// Package server provides HTTPS server with mTLS support for the CoCo sidecar
package server

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/confidential-devhub/cococtl/sidecar/pkg/status"
)

// HTTPSServer represents the HTTPS server with mTLS
type HTTPSServer struct {
	port        int
	serverCert  []byte
	serverKey   []byte
	clientCA    []byte
	collector   *status.Collector
	forwardPort int
}

// NewHTTPSServer creates a new HTTPS server
func NewHTTPSServer(port int, serverCert, serverKey, clientCA []byte,
	collector *status.Collector, forwardPort int) *HTTPSServer {
	return &HTTPSServer{
		port:        port,
		serverCert:  serverCert,
		serverKey:   serverKey,
		clientCA:    clientCA,
		collector:   collector,
		forwardPort: forwardPort,
	}
}

// Start starts the HTTPS server
func (s *HTTPSServer) Start() error {
	log.Println("Initializing HTTPS server...")

	// Load server certificate and key
	log.Println("Loading server TLS certificate and key...")
	cert, err := tls.X509KeyPair(s.serverCert, s.serverKey)
	if err != nil {
		log.Printf("ERROR: Failed to load server certificate: %v", err)
		return fmt.Errorf("failed to load server certificate: %w", err)
	}
	log.Println("Successfully loaded server TLS certificate and key")

	// Create client CA pool
	log.Println("Setting up client CA certificate pool for mTLS...")
	clientCAPool := x509.NewCertPool()
	if !clientCAPool.AppendCertsFromPEM(s.clientCA) {
		log.Println("ERROR: Failed to parse client CA certificate")
		return fmt.Errorf("failed to parse client CA certificate")
	}
	log.Println("Successfully configured client CA certificate pool")

	// TLS configuration with mTLS
	log.Println("Configuring TLS with mTLS (TLS 1.3+)...")
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAPool,
		MinVersion:   tls.VersionTLS13,
	}
	log.Println("TLS configuration complete - client certificates will be required and verified")

	// Setup routes
	log.Println("Registering HTTP routes...")
	mux := http.NewServeMux()

	// Always register API endpoints
	mux.HandleFunc("/api/status", s.serveStatusAPI)
	log.Println("  Registered route: /api/status (Status API)")
	mux.HandleFunc("/api/attestation", s.serveAttestationAPI)
	log.Println("  Registered route: /api/attestation (Attestation API)")

	// Setup port forwarding
	if s.forwardPort > 0 {
		// Serve application at root for seamless proxying
		log.Printf("Port forwarding: serving localhost:%d at root /", s.forwardPort)
		mux.HandleFunc("/dashboard", s.serveDashboard)
		log.Println("  Registered route: /dashboard (Dashboard)")
		mux.Handle("/", s.createReverseProxy(s.forwardPort))
		log.Printf("  Registered route: / (Forward to localhost:%d)", s.forwardPort)
	} else {
		// No port forwarding: just dashboard
		log.Println("No port forwarding configured")
		mux.HandleFunc("/", s.serveDashboard)
		log.Println("  Registered route: / (Dashboard)")
	}

	// Create HTTPS server
	server := &http.Server{
		Addr:              fmt.Sprintf(":%d", s.port),
		Handler:           loggingMiddleware(mux),
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 10 * time.Second,
	}

	log.Printf("HTTPS server listening on :%d (mTLS enabled)", s.port)
	return server.ListenAndServeTLS("", "")
}

func (s *HTTPSServer) serveDashboard(w http.ResponseWriter, r *http.Request) {
	// Get client certificate info
	clientCN := ""
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		clientCN = r.TLS.PeerCertificates[0].Subject.CommonName
	}
	log.Printf("Serving dashboard to client: %s", clientCN)

	status := s.collector.Collect()
	html := generateDashboard(status, clientCN)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if _, err := w.Write([]byte(html)); err != nil {
		log.Printf("ERROR: Failed to write dashboard response: %v", err)
	}
	log.Printf("Dashboard served successfully to client: %s", clientCN)
}

func (s *HTTPSServer) serveStatusAPI(w http.ResponseWriter, _ *http.Request) {
	log.Println("API request received: /api/status")
	status := s.collector.Collect()
	json := status.ToJSON()
	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(json); err != nil {
		log.Printf("ERROR: Failed to write status API response: %v", err)
	}
	log.Printf("Status API response sent: pod=%s, namespace=%s, attested=%v", status.PodName, status.Namespace, status.Attested)
}

func (s *HTTPSServer) serveAttestationAPI(w http.ResponseWriter, _ *http.Request) {
	log.Println("API request received: /api/attestation")
	attestation := s.collector.GetAttestation()
	json := attestation.ToJSON()
	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(json); err != nil {
		log.Printf("ERROR: Failed to write attestation API response: %v", err)
	}
	log.Printf("Attestation API response sent: status=%s", attestation.Status)
}

func (s *HTTPSServer) createReverseProxy(targetPort int) http.Handler {
	target := &url.URL{
		Scheme: "http",
		Host:   fmt.Sprintf("localhost:%d", targetPort),
	}

	// Create reverse proxy that forwards all requests directly to the backend
	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			req.Host = target.Host
			log.Printf("Proxying request to port %d: %s %s", targetPort, req.Method, req.URL.Path)
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("ERROR: Reverse proxy error for port %d, path %s: %v", targetPort, r.URL.Path, err)
			http.Error(w, fmt.Sprintf("Proxy error: %v", err), http.StatusBadGateway)
		},
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxy.ServeHTTP(w, r)
	})
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientCN := "unknown"
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			clientCN = r.TLS.PeerCertificates[0].Subject.CommonName
		}
		log.Printf("Request: %s %s (client: %s)", r.Method, r.URL.Path, clientCN)
		next.ServeHTTP(w, r)
	})
}

func generateDashboard(status *status.Status, clientCN string) string {
	attestationStatus := "Unavailable"
	if status.Attested {
		attestationStatus = "Attested"
	}

	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>CoCo Pod Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; }
        h1 { color: #333; border-bottom: 2px solid #007bff; padding-bottom: 10px; }
        table { border-collapse: collapse; width: 100%%; margin: 15px 0; }
        th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        th { background-color: #007bff; color: white; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        .client-info { background: #e7f3ff; padding: 10px; border-radius: 5px; margin: 15px 0; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 CoCo Pod Dashboard</h1>
        <div class="client-info">
            <strong>Connected as:</strong> %s (via mTLS)
        </div>
        <h2>Pod Information</h2>
        <table>
            <tr><th>Property</th><th>Value</th></tr>
            <tr><td>Pod Name</td><td>%s</td></tr>
            <tr><td>Pod Namespace</td><td>%s</td></tr>
            <tr><td>Attestation Status</td><td>%s</td></tr>
        </table>
    </div>
</body>
</html>`, clientCN, status.PodName, status.Namespace, attestationStatus)
}

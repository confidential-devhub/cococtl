// Package server provides HTTPS server with mTLS support for the CoCo sidecar
package server

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
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
			// Save original values before modification
			originalHost := req.Host
			originalScheme := "https" // We're receiving HTTPS

			// Update URL for backend
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host

			// IMPORTANT: Do NOT override req.Host - preserve original for CORS
			// This allows applications like Jupyter to validate the Origin header correctly

			// Set standard reverse proxy headers
			if req.Header.Get("X-Forwarded-Host") == "" {
				req.Header.Set("X-Forwarded-Host", originalHost)
			}
			if req.Header.Get("X-Forwarded-Proto") == "" {
				req.Header.Set("X-Forwarded-Proto", originalScheme)
			}
			if req.Header.Get("X-Forwarded-For") == "" {
				// Get client IP from remote address
				if clientIP, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
					req.Header.Set("X-Forwarded-For", clientIP)
					req.Header.Set("X-Real-IP", clientIP)
				}
			}

			log.Printf("Proxying request to port %d: %s %s (Host: %s)", targetPort, req.Method, req.URL.Path, originalHost)
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
	attestationBadge := `<span class="badge badge-unavailable">Unavailable</span>`
	if status.Attested {
		attestationBadge = `<span class="badge badge-success">✓ Attested</span>`
	}

	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Confidential Containers - Pod Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #f5f7fa 0%%, #c3cfe2 100%%);
            min-height: 100vh;
            padding: 20px;
        }
        .header {
            text-align: center;
            margin-bottom: 30px;
            padding: 20px;
            background: white;
            border-radius: 12px;
            box-shadow: 0 4px 6px rgba(0, 92, 148, 0.1);
        }
        .logo {
            width: 80px;
            height: 80px;
            margin: 0 auto 15px;
        }
        .header h1 {
            color: #005c94;
            font-size: 28px;
            font-weight: 600;
            margin-bottom: 5px;
        }
        .header .subtitle {
            color: #666;
            font-size: 14px;
        }
        .container {
            max-width: 1000px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 12px;
            box-shadow: 0 4px 6px rgba(0, 92, 148, 0.1);
        }
        .client-info {
            background: linear-gradient(135deg, #005c94 0%%, #0077ba 100%%);
            color: white;
            padding: 15px 20px;
            border-radius: 8px;
            margin-bottom: 25px;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }
        .client-info .icon {
            font-size: 24px;
            margin-right: 10px;
        }
        .client-info .text {
            flex: 1;
        }
        .client-info strong {
            font-weight: 600;
        }
        h2 {
            color: #005c94;
            font-size: 20px;
            font-weight: 600;
            margin: 25px 0 15px;
            padding-bottom: 10px;
            border-bottom: 3px solid #ff4d4d;
        }
        table {
            border-collapse: collapse;
            width: 100%%;
            margin: 15px 0;
            border-radius: 8px;
            overflow: hidden;
        }
        th, td {
            padding: 14px 18px;
            text-align: left;
        }
        th {
            background: linear-gradient(135deg, #005c94 0%%, #0077ba 100%%);
            color: white;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 12px;
            letter-spacing: 0.5px;
        }
        tr:nth-child(even) {
            background-color: #f8f9fa;
        }
        tr:hover {
            background-color: #e8f4f8;
        }
        td {
            border-bottom: 1px solid #e0e0e0;
            color: #333;
        }
        .badge {
            display: inline-block;
            padding: 6px 12px;
            border-radius: 20px;
            font-size: 13px;
            font-weight: 600;
        }
        .badge-success {
            background-color: #28a745;
            color: white;
        }
        .badge-unavailable {
            background-color: #ffc107;
            color: #333;
        }
        .footer {
            text-align: center;
            margin-top: 25px;
            padding-top: 20px;
            border-top: 1px solid #e0e0e0;
            color: #666;
            font-size: 13px;
        }
        .footer a {
            color: #005c94;
            text-decoration: none;
            font-weight: 600;
        }
        .footer a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="header">
        <img class="logo" src="https://raw.githubusercontent.com/cncf/artwork/main/projects/confidential-containers/icon/color/confidential-containers-icon.svg" alt="Confidential Containers">
        <h1>Confidential Containers</h1>
        <div class="subtitle">Secure Access Dashboard</div>
    </div>
    <div class="container">
        <div class="client-info">
            <div class="text">
                <span class="icon">🔐</span>
                <strong>Authenticated via mTLS:</strong> %s
            </div>
        </div>
        <h2>Pod Information</h2>
        <table>
            <tr><th>Property</th><th>Value</th></tr>
            <tr><td><strong>Pod Name</strong></td><td>%s</td></tr>
            <tr><td><strong>Namespace</strong></td><td>%s</td></tr>
            <tr><td><strong>Attestation Status</strong></td><td>%s</td></tr>
        </table>
        <div class="footer">
            Powered by <a href="https://confidentialcontainers.org" target="_blank">Confidential Containers</a> - A CNCF Sandbox Project
        </div>
    </div>
</body>
</html>`, clientCN, status.PodName, status.Namespace, attestationBadge)
}

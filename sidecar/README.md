# CoCo Secure Access Sidecar

A secure access sidecar for Confidential Containers (CoCo) that provides mTLS-secured HTTPS access to confidential pods.

## Overview

This sidecar container runs alongside your application in a CoCo pod and provides:

- **mTLS-secured HTTPS** service for attestation status and environment information
- **Port forwarding** to expose primary container services over HTTPS
- **Certificate management** via Trustee KBS with attestation-based retrieval

## Trust Model

The sidecar addresses the CoCo trust model where the **control plane is untrusted**:

- TLS terminates inside the sidecar (in TEE)
- Certificates retrieved via attestation from Trustee KBS
- Client authentication via mTLS with client certificates

## Features

### HTTPS Dashboard
- Web-based dashboard showing pod status
- REST API endpoints for status and attestation details
- Client certificate authentication (mTLS)

### Port Forwarding
- Reverse proxy for a single application port
- HTTPS-secured access to application service like Jupyter etc.
- Application served at root `/` for seamless integration
- No application configuration needed (no base_url required)
- Configurable via `FORWARD_PORT` environment variable

## Building

### Local Build
```bash
make build
```

### Docker Image
```bash
make docker-build
```

To build and push to registry:
```bash
make docker-push TAG=v0.1.0
```

## Configuration

The sidecar is configured via environment variables (set by kubectl-coco):

| Variable | Description | Default |
|----------|-------------|---------|
| `TLS_CERT_URI` | Server TLS certificate KBS URI | Required |
| `TLS_KEY_URI` | Server TLS key KBS URI | Required |
| `CLIENT_CA_URI` | Client CA certificate KBS URI (for mTLS) | Required |
| `HTTPS_PORT` | HTTPS server port | 8443 |
| `FORWARD_PORT` | Port to forward from the application container | Empty |

## Usage

The sidecar is automatically injected by kubectl-coco when using the `--sidecar` flag:

```bash
kubectl coco apply -f app.yaml --sidecar
```

### Accessing the Sidecar

**Important:** kubectl port-forward does NOT work with mTLS connections.
Use NodePort or Ingress.

**Option 1: NodePort Service**

```bash
# Create NodePort service
kubectl apply -f - <<EOF
apiVersion: v1
kind: Service
metadata:
  name: myapp-sidecar
spec:
  type: NodePort
  selector:
    app: myapp
  ports:
  - name: https
    port: 8443
    targetPort: 8443
EOF

# Get service endpoints
NODE_IP=$(kubectl get nodes -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')
HTTPS_PORT=$(kubectl get svc myapp-sidecar -o jsonpath='{.spec.ports[?(@.name=="https")].nodePort}')

# Access HTTPS Dashboard
curl -k --cert ~/.kube/coco-sidecar/client-cert.pem \
     --key ~/.kube/coco-sidecar/client-key.pem \
     https://$NODE_IP:$HTTPS_PORT/
```

**Port Forwarding:**

With port forwarding configured, the application is served at root:

```bash
# Access the forwarded application at root
curl -k --cert ~/.kube/coco-sidecar/client-cert.pem \
     --key ~/.kube/coco-sidecar/client-key.pem \
     https://$NODE_IP:$HTTPS_PORT/

# Access the dashboard at /dashboard
curl -k --cert ~/.kube/coco-sidecar/client-cert.pem \
     --key ~/.kube/coco-sidecar/client-key.pem \
     https://$NODE_IP:$HTTPS_PORT/dashboard
```

## Certificate Setup

Certificates are automatically generated and managed by `kubectl-coco`.

### One-Time Setup (Client CA)

Initialize sidecar certificates once per cluster:

```bash
kubectl coco init --enable-sidecar
```

This command:
1. Generates Client CA (4096-bit RSA, 10-year validity)
2. Generates client certificate for "developer" user (1-year validity)
3. Uploads Client CA to Trustee KBS at `kbs:///default/sidecar-tls/client-ca`
4. Saves certificates locally to `~/.kube/coco-sidecar/`:
   - `ca-cert.pem` and `ca-key.pem` (Client CA)
   - `client-cert.pem` and `client-key.pem` (for accessing sidecars)

### Per-Application Server Certificates

Server certificates are automatically generated during deployment:

```bash
# Auto-generates server certificate with node IPs and service DNS
kubectl coco apply -f app.yaml --sidecar

# Custom SANs for LoadBalancer or Ingress access
kubectl coco apply -f app.yaml --sidecar \
  --sidecar-san-ips=203.0.113.10 \
  --sidecar-san-dns=myapp.example.com

# Skip auto-detection and use only custom SANs
kubectl coco apply -f app.yaml --sidecar \
  --sidecar-san-ips=10.0.0.1 \
  --sidecar-skip-auto-sans
```

Each application gets a unique server certificate with:
- Common Name: application name
- SANs: Auto-detected node IPs + service DNS (or custom SANs)
- Uploaded to KBS at `kbs:///<namespace>/sidecar-tls-<appName>/server-{cert|key}`
- Signed by the Client CA for mTLS authentication

**Certificate Storage Summary:**
- Client CA: `~/.kube/coco-sidecar/ca-*.pem` (used to sign server certs)
- Client cert: `~/.kube/coco-sidecar/client-*.pem` (for accessing sidecars via mTLS)
- Server certs: Generated per-app, uploaded to KBS (not stored locally)

### Browser Access Setup

To access the sidecar via browser (with mTLS), create a PKCS12 bundle from the client certificate:

```bash
# Create PKCS12 bundle for browser import
cd ~/.kube/coco-sidecar
openssl pkcs12 -export \
  -in client-cert.pem \
  -inkey client-key.pem \
  -out client.p12 \
  -name "CoCo Sidecar Client - developer" \
  -passout pass:coco123
```

**macOS:**
1. Import client certificate to Keychain:
   ```bash
   open ~/.kube/coco-sidecar/client.p12
   # Enter password: coco123
   ```

2. Get the NodePort service endpoint:
   ```bash
   NODE_IP=$(kubectl get nodes -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')
   HTTPS_PORT=$(kubectl get svc myapp-sidecar -o jsonpath='{.spec.ports[?(@.name=="https")].nodePort}')
   echo "Access at: https://$NODE_IP:$HTTPS_PORT/"
   ```

3. Open browser to `https://$NODE_IP:$HTTPS_PORT/`

4. Select client certificate when prompted: "CoCo Sidecar Client - developer"

**Linux:**

1. Import client certificate to browser:
   - **Firefox**: Settings → Privacy & Security → Certificates → View Certificates → Your Certificates → Import
   - **Chrome**: Settings → Privacy and Security → Security → Manage Certificates → Your Certificates → Import

2. Select `~/.kube/coco-sidecar/client.p12` and enter password: `coco123`

3. Access the sidecar dashboard at `https://$NODE_IP:$HTTPS_PORT/dashboard`

4. Access the forwarded port at `https://$NODE_IP:$HTTPS_PORT/`

### Verifying Certificates

```bash
cd ~/.kube/coco-sidecar

# Verify client certificate is signed by CA
openssl verify -CAfile ca-cert.pem client-cert.pem

# Test mTLS connection with curl
NODE_IP=$(kubectl get nodes -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')
HTTPS_PORT=$(kubectl get svc myapp-sidecar -o jsonpath='{.spec.ports[?(@.name=="https")].nodePort}')

curl -k --cert client-cert.pem \
     --key client-key.pem \
     https://$NODE_IP:$HTTPS_PORT/
```

## Architecture

```
┌─────────────────────────────────────────┐
│         CoCo Pod (TEE)                  │
│  ┌──────────────┐   ┌───────────────┐  │
│  │ Application  │   │ Sidecar       │  │
│  │ Container    │◄──┤ - HTTPS+mTLS  │  │
│  │              │   │ - Proxy       │  │
│  │              │   │               │  │
│  └──────────────┘   └───────┬───────┘  │
│                             │          │
│                             ▼          │
│                      ┌──────────────┐  │
│                      │ CDH/AA       │  │
│                      │ (fetch certs)│  │
│                      └──────┬───────┘  │
└─────────────────────────────┼──────────┘
                              │
                              ▼
                      ┌───────────────┐
                      │ Trustee KBS   │
                      │ (attestation) │
                      └───────────────┘
```

## Security

- **mTLS only**: No access without valid client certificate
- **Attestation-based**: Certificates retrieved only after TEE verification
- **Environment filtering**: Sensitive vars not exposed
- **TLS 1.3**: Modern cryptography only

## Development

### Run Tests

```bash
make test
```

### Format Code

```bash
make fmt
```

### Run Linter

```bash
make lint
```
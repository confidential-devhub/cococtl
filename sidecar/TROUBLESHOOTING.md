# Sidecar Browser Access Troubleshooting

This guide helps diagnose and fix issues with accessing the sidecar via browser with mTLS.

## Step 1: Verify Sidecar Pod is Running

```bash
# Check if the pod is running and has the sidecar container
kubectl get pods -l app=<your-app-name>

# Check sidecar container logs
kubectl logs <pod-name> -c coco-secure-access

# Look for these messages:
# - "Starting CoCo Secure Access Sidecar..."
# - "Successfully fetched all certificates from KBS"
# - "HTTPS server listening on :8443 (mTLS enabled)"
```

**Expected**: Pod shows 2/2 READY, sidecar logs show "HTTPS server listening"

## Step 2: Verify NodePort Service

```bash
# Check if the service exists
kubectl get svc <service-name>

# Get the NodePort
HTTPS_PORT=$(kubectl get svc <service-name> -o jsonpath='{.spec.ports[?(@.name=="https")].nodePort}')
echo "HTTPS NodePort: $HTTPS_PORT"

# Get node IP
NODE_IP=$(kubectl get nodes -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')
echo "Node IP: $NODE_IP"

# Verify port is listening
nc -zv $NODE_IP $HTTPS_PORT
```

**Expected**: Service exists with type NodePort, port is accessible

## Step 3: Test with curl (Proves mTLS Works)

```bash
cd ~/.kube/coco-sidecar

# Test mTLS connection
curl -v -k --cert client-cert.pem --key client-key.pem \
  https://$NODE_IP:$HTTPS_PORT/

# Look for:
# - "SSL connection using TLSv1.3"
# - "Server certificate:"
# - HTTP 200 response with HTML dashboard
```

**Expected**: Successful connection with HTML dashboard response

**If curl fails**: Check sidecar logs for certificate errors

## Step 4: Check Server Certificate SANs

The server certificate must include the IP/hostname you're accessing.

```bash
# Option A: Check from KBS (requires kubectl exec to trustee pod)
TRUSTEE_POD=$(kubectl get pods -n coco -l app=kbs -o name | head -1)
kubectl exec -n coco $TRUSTEE_POD -- cat /opt/confidential-containers/kbs/repository/default/sidecar-tls-<app-name>/server-cert | openssl x509 -noout -text | grep -A 2 "Subject Alternative Name"

# Expected output should include your NODE_IP:
# X509v3 Subject Alternative Name:
#   DNS:myapp.default.svc.cluster.local, IP Address:10.6.68.31, IP Address:127.0.0.1
```

**Common issue**: If the IP you're accessing is NOT in the SANs, browser will reject the connection.

**Fix**: Regenerate server cert with correct SANs:
```bash
kubectl coco apply -f app.yaml --sidecar --sidecar-san-ips=$NODE_IP
```

## Step 5: Verify Client Certificate in Keychain (macOS)

```bash
# List certificates in keychain
security find-certificate -a -c "CoCo Sidecar Client - developer" | grep "labl"

# Verify the .p12 file is correct
openssl pkcs12 -info -in ~/.kube/coco-sidecar/client.p12 -passin pass:coco123 -noout

# Check certificate can be read
openssl pkcs12 -in ~/.kube/coco-sidecar/client.p12 -passin pass:coco123 -clcerts -nokeys | openssl x509 -noout -subject -issuer
```

**Expected**: Certificate appears in keychain with name "CoCo Sidecar Client - developer"

## Step 6: Browser-Specific Issues

### Issue A: Browser Not Presenting Client Certificate

**Symptoms**: Browser doesn't show certificate selection dialog

**Causes**:
1. **Wrong URL scheme**: Must use `https://` (not `http://`)
2. **Certificate not imported**: Check Keychain Access (macOS) or browser settings
3. **Browser cached a "no certificate" decision**: Clear SSL state

**macOS Safari**:
- Go to Keychain Access → login → Certificates
- Find "CoCo Sidecar Client - developer"
- Double-click → Trust → "Always Trust"

**macOS Chrome**:
- Settings → Privacy and Security → Security → Manage Certificates
- Check if certificate appears under "Your Certificates"
- May need to restart Chrome

**Firefox**:
- Settings → Privacy & Security → View Certificates → Your Certificates
- Import the .p12 file again if not visible

### Issue B: Certificate Validation Error / ERR_CERT_AUTHORITY_INVALID

**Symptoms**: Browser shows "Your connection is not private" or similar

**Cause**: Server certificate is self-signed and not trusted

**Fix Option 1**: Accept the certificate (Click "Advanced" → "Proceed to..." - ONLY for testing)

**Fix Option 2**: Trust the server certificate (macOS):
```bash
# This requires fetching the server cert from the pod first
# Get the server cert from KBS
TRUSTEE_POD=$(kubectl get pods -n coco -l app=kbs -o name | head -1)
kubectl exec -n coco $TRUSTEE_POD -- cat /opt/confidential-containers/kbs/repository/default/sidecar-tls-<app-name>/server-cert > /tmp/server-cert.pem

# Add to system trust store
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain /tmp/server-cert.pem
```

### Issue C: ERR_SSL_CLIENT_AUTH_SIGNATURE_FAILED

**Symptoms**: Browser shows "client authentication failed" error

**Cause**: Client certificate is in keychain but browser can't use it

**Fix**:
1. Remove and re-import the .p12 file
2. When importing, ensure you import to "login" keychain (not "System")
3. After import, find the certificate in Keychain Access and set Trust to "Always Trust"

### Issue D: Browser Shows Certificate Selection but Connection Still Fails

**Symptoms**: Browser shows cert picker, you select the cert, but connection fails

**Debugging**:
```bash
# Check sidecar logs during the connection attempt
kubectl logs <pod-name> -c coco-secure-access --tail=50

# Look for:
# - "Request: GET / (client: developer)" - means mTLS worked!
# - "ERROR: Failed to ..." - shows the specific error
```

## Step 7: Check Browser Developer Console

1. Open the browser developer console (F12 or Cmd+Opt+I)
2. Go to the Console tab
3. Try accessing the URL
4. Look for error messages

Common errors:
- `ERR_CERT_AUTHORITY_INVALID` - Server cert not trusted
- `ERR_SSL_CLIENT_AUTH_SIGNATURE_FAILED` - Client cert problem
- `ERR_CONNECTION_REFUSED` - Service/pod not running or wrong port
- `ERR_SSL_PROTOCOL_ERROR` - TLS handshake failure

## Step 8: Verify Full mTLS Chain

```bash
# Test the full TLS handshake with verbose output
openssl s_client -connect $NODE_IP:$HTTPS_PORT \
  -cert ~/.kube/coco-sidecar/client-cert.pem \
  -key ~/.kube/coco-sidecar/client-key.pem \
  -CAfile ~/.kube/coco-sidecar/ca-cert.pem \
  -showcerts

# Look for:
# - "Verify return code: 0 (ok)" or acceptable error
# - "Server certificate" section
# - "Acceptable client certificate CA names" (should show your CA)
```

## Common Solutions

### Solution 1: Regenerate Everything

If nothing works, start fresh:

```bash
# 1. Delete the pod
kubectl delete pod <pod-name>

# 2. Remove old certificates from keychain (macOS)
security delete-certificate -c "CoCo Sidecar Client - developer"

# 3. Regenerate and redeploy
kubectl coco apply -f app.yaml --sidecar --sidecar-san-ips=$NODE_IP

# 4. Recreate .p12 and import
cd ~/.kube/coco-sidecar
openssl pkcs12 -export -in client-cert.pem -inkey client-key.pem \
  -out client.p12 -name "CoCo Sidecar Client - developer" \
  -passout pass:coco123
open client.p12

# 5. Clear browser SSL state and try again
```

### Solution 2: Use IP Instead of Hostname

If you're trying to access by hostname but it's not in SANs:

```bash
# Access by IP directly
echo "Accessing: https://$NODE_IP:$HTTPS_PORT/"
```

### Solution 3: Check Firewall/Network

```bash
# Ensure NodePort is accessible
sudo lsof -i :$HTTPS_PORT

# Check if there's a firewall blocking
sudo iptables -L -n | grep $HTTPS_PORT
```

## Quick Diagnostic Script

Run this to check everything at once:

```bash
#!/bin/bash
set -e

APP_NAME="myapp"  # Change to your app name
SERVICE_NAME="${APP_NAME}-sidecar"

echo "=== Sidecar Browser Access Diagnostics ==="
echo ""

echo "1. Checking pod status..."
kubectl get pods -l app=$APP_NAME
echo ""

echo "2. Checking service..."
kubectl get svc $SERVICE_NAME
NODE_IP=$(kubectl get nodes -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')
HTTPS_PORT=$(kubectl get svc $SERVICE_NAME -o jsonpath='{.spec.ports[?(@.name=="https")].nodePort}')
echo "Access URL: https://$NODE_IP:$HTTPS_PORT/"
echo ""

echo "3. Checking sidecar logs (last 10 lines)..."
POD_NAME=$(kubectl get pods -l app=$APP_NAME -o jsonpath='{.items[0].metadata.name}')
kubectl logs $POD_NAME -c coco-secure-access --tail=10
echo ""

echo "4. Testing curl connection..."
cd ~/.kube/coco-sidecar
curl -v -k --cert client-cert.pem --key client-key.pem \
  "https://$NODE_IP:$HTTPS_PORT/" 2>&1 | grep -E "SSL connection|HTTP|error"
echo ""

echo "5. Checking client certificate in keychain..."
security find-certificate -a -c "CoCo Sidecar Client - developer" | grep -c "labl" || echo "Not found in keychain!"
echo ""

echo "=== Diagnostics Complete ==="
echo "If curl works but browser doesn't:"
echo "  - Issue is with browser certificate configuration"
echo "  - Try removing and re-importing the .p12 file"
echo "  - Make sure to accept security warnings for self-signed server cert"
```

## Still Not Working?

Provide these details for further help:
1. Output of the diagnostic script above
2. Browser type and version
3. Exact error message from browser
4. Sidecar container logs: `kubectl logs <pod> -c coco-secure-access`
5. Output of: `openssl s_client -connect $NODE_IP:$HTTPS_PORT`

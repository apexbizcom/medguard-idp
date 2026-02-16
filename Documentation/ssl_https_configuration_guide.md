# SSL/HTTPS Configuration Guide for SAML SSO Production

## Overview

For production deployment of SAML SSO, you must use HTTPS for:
- ORDS (Oracle REST Data Services)
- Keycloak (Identity Provider)
- All SAML endpoints

This guide covers the complete SSL setup.

---

## Part 1: Generate SSL Certificates

### Option A: Self-Signed Certificates (Development/Testing)

```bash
# Create a directory for certificates
mkdir -p ~/ssl-certs
cd ~/ssl-certs

# Generate private key
openssl genrsa -out server.key 2048

# Generate certificate signing request
openssl req -new -key server.key -out server.csr \
    -subj "/C=US/ST=Georgia/L=Atlanta/O=ComplianceVault/CN=localhost"

# Generate self-signed certificate (valid for 365 days)
openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt

# Create PKCS12 keystore for Java applications
openssl pkcs12 -export -in server.crt -inkey server.key \
    -out keystore.p12 -name server -password pass:changeit

# Convert to JKS format (if needed)
keytool -importkeystore -srckeystore keystore.p12 -srcstoretype pkcs12 \
    -destkeystore keystore.jks -deststoretype JKS \
    -srcstorepass changeit -deststorepass changeit
```

### Option B: Let's Encrypt Certificates (Production)

```bash
# Install certbot
brew install certbot  # macOS
# or
sudo apt install certbot  # Ubuntu

# Generate certificate for your domain
sudo certbot certonly --standalone -d your-domain.com

# Certificates will be in /etc/letsencrypt/live/your-domain.com/
# - fullchain.pem (certificate)
# - privkey.pem (private key)
```

### Option C: Commercial Certificate

Purchase from providers like DigiCert, Comodo, or GoDaddy and follow their instructions.

---

## Part 2: Configure ORDS for HTTPS

### Option A: ORDS Standalone with HTTPS

1. **Create ORDS SSL configuration:**

```bash
# Stop ORDS if running
# Ctrl+C

# Configure HTTPS
ords config set standalone.https.port 8443
ords config set standalone.https.cert /path/to/server.crt
ords config set standalone.https.cert.key /path/to/server.key

# Or using keystore
ords config set standalone.https.port 8443
ords config set standalone.https.keystore /path/to/keystore.p12
ords config set standalone.https.keystore.password changeit
ords config set standalone.https.keystore.type PKCS12

# Optionally disable HTTP (force HTTPS)
ords config set standalone.http.port 0

# Start ORDS
ords serve
```

2. **Verify HTTPS is working:**

```bash
curl -k https://localhost:8443/ords/
```

### Option B: ORDS Behind Reverse Proxy (Recommended for Production)

Using **nginx** as a reverse proxy:

1. **Install nginx:**
```bash
brew install nginx  # macOS
sudo apt install nginx  # Ubuntu
```

2. **Configure nginx:**

Create `/etc/nginx/sites-available/ords-ssl`:

```nginx
server {
    listen 443 ssl;
    server_name your-domain.com;

    ssl_certificate /path/to/fullchain.pem;
    ssl_certificate_key /path/to/privkey.pem;
    
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;

    location / {
        proxy_pass http://localhost:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Important for SAML
        proxy_buffer_size 128k;
        proxy_buffers 4 256k;
        proxy_busy_buffers_size 256k;
    }
}

# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name your-domain.com;
    return 301 https://$server_name$request_uri;
}
```

3. **Enable and start nginx:**
```bash
sudo ln -s /etc/nginx/sites-available/ords-ssl /etc/nginx/sites-enabled/
sudo nginx -t  # Test configuration
sudo systemctl restart nginx
```

---

## Part 3: Configure Keycloak for HTTPS

### Option A: Keycloak Standalone

1. **Copy certificates to Keycloak:**

```bash
# For Keycloak 17+ (Quarkus)
cp server.crt /path/to/keycloak/conf/server.crt.pem
cp server.key /path/to/keycloak/conf/server.key.pem
```

2. **Configure Keycloak:**

Edit `conf/keycloak.conf`:

```properties
# HTTPS settings
https-port=8543
https-certificate-file=/path/to/keycloak/conf/server.crt.pem
https-certificate-key-file=/path/to/keycloak/conf/server.key.pem

# Disable HTTP (production)
http-enabled=false

# Or keep HTTP for health checks
http-enabled=true
http-port=8180
```

3. **Start Keycloak:**
```bash
/path/to/keycloak/bin/kc.sh start
```

### Option B: Keycloak in Docker

```bash
docker run -d \
  --name keycloak \
  -p 8543:8443 \
  -e KEYCLOAK_ADMIN=admin \
  -e KEYCLOAK_ADMIN_PASSWORD=admin \
  -v /path/to/server.crt:/etc/x509/https/tls.crt \
  -v /path/to/server.key:/etc/x509/https/tls.key \
  quay.io/keycloak/keycloak:latest \
  start --hostname=localhost
```

---

## Part 4: Update SAML Configuration for HTTPS

### 1. Update Keycloak Client Configuration

In Keycloak Admin Console:

1. Go to **Clients** → **medguard-dms**
2. Update these URLs to HTTPS:

| Setting | Value |
|---------|-------|
| Root URL | `https://your-domain.com` |
| Valid Redirect URIs | `https://your-domain.com/*` |
| Master SAML Processing URL | `https://your-domain.com/ords/compliancevault/api/v1/auth/saml/acs` |
| Logout Service POST Binding URL | `https://your-domain.com/ords/compliancevault/api/v1/auth/saml/slo` |

3. **Enable "Force POST Binding"** for added security
4. **Enable "Sign Assertions"** and **"Sign Documents"**
5. Save changes

### 2. Update ORDS CORS Configuration

```bash
ords config set security.externalSessionTrustedOrigins "null,https://your-domain.com,https://keycloak-domain.com"
```

### 3. Update Database Configuration

```sql
-- Update IdP configuration with HTTPS URLs
UPDATE DMS.SAML_IDP_CONFIG 
SET config_value = 'https://keycloak-domain.com:8543/realms/compliancevault'
WHERE config_key = 'IDP_ENTITY_ID' AND tenant_id = 1;

UPDATE DMS.SAML_IDP_CONFIG 
SET config_value = 'https://keycloak-domain.com:8543/realms/compliancevault/protocol/saml'
WHERE config_key = 'IDP_SSO_URL' AND tenant_id = 1;

UPDATE DMS.SAML_IDP_CONFIG 
SET config_value = 'https://keycloak-domain.com:8543/realms/compliancevault/protocol/saml'
WHERE config_key = 'IDP_SLO_URL' AND tenant_id = 1;

UPDATE DMS.SAML_IDP_CONFIG 
SET config_value = 'https://your-domain.com/ords/compliancevault/api/v1/auth/saml/acs'
WHERE config_key = 'SP_ACS_URL' AND tenant_id = 1;

COMMIT;
```

### 4. Update ORDS REST Handler URLs

```sql
-- Update the REST handler to use HTTPS
BEGIN
    ORDS.DEFINE_HANDLER(
        p_module_name   => 'cloud.compliancevault.medguard.services',
        p_pattern       => 'auth/saml/acs',
        p_method        => 'POST',
        p_source_type   => 'plsql/block',
        p_mimes_allowed => 'application/x-www-form-urlencoded',
        p_source        => q'[
DECLARE
    lv_saml_response    CLOB;
    lv_relay_state      VARCHAR2(4000);
    lv_token            VARCHAR2(64);
    lv_client_ip        VARCHAR2(50);
    lv_user_agent       VARCHAR2(1000);
    lv_redirect_url     VARCHAR2(4000);
    lv_apex_app_id      NUMBER := 100;
    lv_apex_page_id     NUMBER := 9998;
    ln_tenant_id        NUMBER := 1;
    lv_base_url         VARCHAR2(500) := 'https://your-domain.com';  -- UPDATE THIS
BEGIN
    lv_saml_response := :SAMLResponse;
    lv_relay_state := :RelayState;
    
    lv_client_ip := OWA_UTIL.GET_CGI_ENV('REMOTE_ADDR');
    lv_user_agent := SUBSTR(OWA_UTIL.GET_CGI_ENV('HTTP_USER_AGENT'), 1, 1000);
    
    IF lv_saml_response IS NULL THEN
        HTP.P('<!DOCTYPE html><html><body>');
        HTP.P('<h1>Error</h1><p>No SAML response received.</p>');
        HTP.P('</body></html>');
        RETURN;
    END IF;
    
    lv_token := DMS.SAML_HELPER_PKG.store_saml_response(
        pn_tenant_id     => ln_tenant_id,
        pc_saml_response => lv_saml_response,
        pv_relay_state   => lv_relay_state,
        pv_client_ip     => lv_client_ip,
        pv_user_agent    => lv_user_agent
    );
    
    lv_redirect_url := lv_base_url || '/ords/f?p=' 
        || lv_apex_app_id || ':' || lv_apex_page_id || ':0::NO::P9998_SAML_TOKEN:' || lv_token;
    
    HTP.P('<!DOCTYPE html>');
    HTP.P('<html><head><title>Authenticating...</title></head>');
    HTP.P('<body onload="document.forms[0].submit();">');
    HTP.P('<form method="GET" action="' || lv_base_url || '/ords/f">');
    HTP.P('<input type="hidden" name="p" value="' || lv_apex_app_id || ':' || lv_apex_page_id || ':0::NO::P9998_SAML_TOKEN:' || lv_token || '"/>');
    HTP.P('<noscript><button type="submit">Continue</button></noscript>');
    HTP.P('</form>');
    HTP.P('<p>Completing authentication...</p>');
    HTP.P('</body></html>');
    
EXCEPTION
    WHEN OTHERS THEN
        HTP.P('<!DOCTYPE html><html><body>');
        HTP.P('<h1>Error</h1><p>' || SQLERRM || '</p>');
        HTP.P('</body></html>');
END;
]'
    );
    COMMIT;
END;
/
```

### 5. Update APEX Application

1. Go to **Shared Components** → **Application Definition Attributes**
2. Set **"Home Link"** to use HTTPS
3. Set **"Login URL"** to use HTTPS

Or use Substitution Strings:
- Go to **Shared Components** → **Application Definition** → **Substitution Strings**
- Add: `APP_BASE_URL` = `https://your-domain.com`

---

## Part 5: Require HTTPS in Keycloak Realm

1. Go to **Keycloak Admin Console** → **Realm Settings**
2. Under **General**, set **"Require SSL"** to:
   - **"external requests"** (for production)
   - This requires HTTPS for all external (non-localhost) connections

---

## Part 6: Security Best Practices

### 1. TLS Configuration

Ensure strong TLS settings:

```nginx
# In nginx configuration
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
ssl_prefer_server_ciphers on;
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 1d;
ssl_session_tickets off;

# HSTS (HTTP Strict Transport Security)
add_header Strict-Transport-Security "max-age=63072000" always;
```

### 2. Certificate Validation

For production, always:
- Use certificates from trusted Certificate Authorities
- Set up automatic certificate renewal (Let's Encrypt + certbot)
- Monitor certificate expiration

### 3. Keycloak Security Headers

In Keycloak, enable security headers:
1. Go to **Realm Settings** → **Security Defenses**
2. Configure:
   - X-Frame-Options: SAMEORIGIN
   - Content-Security-Policy
   - X-Content-Type-Options: nosniff

---

## Part 7: Testing HTTPS Configuration

### 1. Test ORDS HTTPS

```bash
# Test direct HTTPS access
curl -v https://your-domain.com/ords/

# Check certificate
openssl s_client -connect your-domain.com:443 -servername your-domain.com
```

### 2. Test Keycloak HTTPS

```bash
# Test Keycloak HTTPS
curl -v https://keycloak-domain.com:8543/realms/compliancevault/.well-known/openid-configuration
```

### 3. Test Complete SAML Flow

1. Navigate to: `https://your-domain.com/ords/f?p=100:LOGIN`
2. Click "Login with SSO"
3. Verify redirect to Keycloak uses HTTPS
4. Complete login
5. Verify redirect back to APEX uses HTTPS
6. Test logout

---

## Troubleshooting

### Issue: Mixed Content Warnings

**Symptom:** Browser blocks requests due to mixed HTTP/HTTPS
**Fix:** Ensure ALL URLs use HTTPS consistently

### Issue: Certificate Not Trusted

**Symptom:** Browser shows security warning
**Fix:** 
- Use a certificate from a trusted CA
- Or import self-signed cert into browser/OS trust store

### Issue: CORS Errors After HTTPS

**Symptom:** 403 CORS errors
**Fix:** Update ORDS trusted origins to include HTTPS URLs

```bash
ords config set security.externalSessionTrustedOrigins "null,https://your-domain.com"
```

### Issue: Redirect Loop

**Symptom:** Infinite redirects between HTTP and HTTPS
**Fix:** Ensure consistent protocol usage in all configurations

---

## Summary Checklist

- [ ] Generate SSL certificates
- [ ] Configure ORDS for HTTPS (direct or via proxy)
- [ ] Configure Keycloak for HTTPS
- [ ] Update Keycloak client URLs to HTTPS
- [ ] Update SAML_IDP_CONFIG table with HTTPS URLs
- [ ] Update ORDS REST handler URLs
- [ ] Update APEX application settings
- [ ] Set Keycloak realm to require SSL
- [ ] Test complete SAML flow over HTTPS
- [ ] Enable HSTS headers
- [ ] Set up certificate renewal monitoring

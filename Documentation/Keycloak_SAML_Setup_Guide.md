# Keycloak SAML Identity Provider Setup Guide

## Complete Step-by-Step Instructions for MedGuard-DMS Integration

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Install and Start Keycloak](#2-install-and-start-keycloak)
3. [Create Realm](#3-create-realm)
4. [Create SAML Client](#4-create-saml-client)
5. [Configure SAML Settings](#5-configure-saml-settings)
6. [Configure Attribute Mappers](#6-configure-attribute-mappers)
7. [Create Test User](#7-create-test-user)
8. [Get Keycloak Certificate](#8-get-keycloak-certificate)
9. [Test Keycloak](#9-test-keycloak)
10. [Docker Commands Reference](#10-docker-commands-reference)
11. [Troubleshooting](#11-troubleshooting)

---

## 1. Prerequisites

Before starting, ensure you have:

- **Docker Desktop** installed and running on your Mac
- **Port 8180** available (Keycloak will run here)
- **Port 8080** available (APEX/ORDS runs here)
- Your MedGuard-DMS APEX application accessible at `http://localhost:8080/ords/r/compliancevault/medguard-dms/`

---

## 2. Install and Start Keycloak

### 2.1 Start Keycloak with Docker

Open Terminal and run:

```bash
docker run -d \
  --name keycloak-dev \
  -p 8180:8080 \
  -e KEYCLOAK_ADMIN=admin \
  -e KEYCLOAK_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak:latest \
  start-dev
```

**What this command does:**
- `-d` runs container in background
- `--name keycloak-dev` names the container for easy reference
- `-p 8180:8080` maps container port 8080 to your Mac's port 8180
- `-e KEYCLOAK_ADMIN=admin` sets admin username
- `-e KEYCLOAK_ADMIN_PASSWORD=admin` sets admin password
- `start-dev` runs Keycloak in development mode

### 2.2 Wait for Keycloak to Start

First run will download the image (~400MB). You'll see:

```
Unable to find image 'quay.io/keycloak/keycloak:latest' locally
latest: Pulling from keycloak/keycloak
...downloading...
Status: Downloaded newer image for quay.io/keycloak/keycloak:latest
```

This is normal - Docker is downloading Keycloak.

### 2.3 Verify Keycloak is Running

Wait 30-60 seconds after download completes, then open:

**http://localhost:8180/admin**

You should see the Keycloak Admin Console login page.

### 2.4 Log In to Admin Console

- **Username:** `admin`
- **Password:** `admin`

You should now see the Keycloak Admin Console dashboard.

---

## 3. Create Realm

A "Realm" in Keycloak is like a tenant - it contains users, applications, and settings.

### 3.1 Create New Realm

1. Click the dropdown in the **top-left corner** that shows **"master"**

2. Click **"Create realm"**

3. Enter the following:
   - **Realm name:** `compliancevault`

4. Click **"Create"**

### 3.2 Verify Realm Created

You should now see **"compliancevault"** in the top-left dropdown instead of "master".

---

## 4. Create SAML Client

A "Client" in Keycloak represents your application that will use Keycloak for authentication.

### 4.1 Navigate to Clients

1. In the left menu, click **"Clients"**

2. Click the **"Create client"** button (blue button, top right)

### 4.2 General Settings

1. **Client type:** Select **SAML**

2. **Client ID:** `medguard-dms`

3. Click **"Next"**

### 4.3 Login Settings

1. **Root URL:** `http://localhost:8080`

2. **Home URL:** `http://localhost:8080/ords/r/compliancevault/medguard-dms/home`

3. **Valid redirect URIs:** `http://localhost:8080/*`

4. Click **"Save"**

---

## 5. Configure SAML Settings

After creating the client, you'll be on the client settings page.

### 5.1 Settings Tab

Click the **"Settings"** tab if not already selected.

### 5.2 SAML Capabilities Section

Scroll down to find "SAML capabilities" and configure:

| Setting | Value |
|---------|-------|
| **Name ID format** | email |
| **Force name ID format** | **ON** (toggle switch) |

### 5.3 Signature and Encryption Section

| Setting | Value |
|---------|-------|
| **Sign documents** | **ON** |
| **Sign assertions** | **ON** |

### 5.4 Login Settings Section

Scroll up to find these settings:

| Setting | Value |
|---------|-------|
| **Master SAML Processing URL** | `http://localhost:8080/ords/r/compliancevault/medguard-dms/saml-acs` |
| **IDP-Initiated SSO URL name** | `medguard-dms` |

### 5.5 Save Settings

Click **"Save"** at the bottom of the page.

---

## 6. Configure Attribute Mappers

Attribute mappers tell Keycloak what user information to include in the SAML response.

### 6.1 Navigate to Client Scopes

1. Click the **"Client scopes"** tab (near the top of the page)

2. Click on **"medguard-dms-dedicated"**

### 6.2 Add Email Mapper

1. Click **"Add mapper"** → **"By configuration"**

2. Select **"User Attribute"**

3. Configure:

| Field | Value |
|-------|-------|
| **Name** | `email` |
| **User Attribute** | `email` |
| **SAML Attribute Name** | `email` |
| **SAML Attribute NameFormat** | Basic |

4. Click **"Save"**

### 6.3 Add First Name Mapper

1. Click **"Add mapper"** → **"By configuration"** → **"User Attribute"**

2. Configure:

| Field | Value |
|-------|-------|
| **Name** | `firstName` |
| **User Attribute** | `firstName` |
| **SAML Attribute Name** | `firstName` |
| **SAML Attribute NameFormat** | Basic |

3. Click **"Save"**

### 6.4 Add Last Name Mapper

1. Click **"Add mapper"** → **"By configuration"** → **"User Attribute"**

2. Configure:

| Field | Value |
|-------|-------|
| **Name** | `lastName` |
| **User Attribute** | `lastName` |
| **SAML Attribute Name** | `lastName` |
| **SAML Attribute NameFormat** | Basic |

3. Click **"Save"**

### 6.5 Add Groups Mapper

1. Click **"Add mapper"** → **"By configuration"**

2. Select **"Group list"**

3. Configure:

| Field | Value |
|-------|-------|
| **Name** | `groups` |
| **Group attribute name** | `groups` |
| **SAML Attribute NameFormat** | Basic |
| **Single Group Attribute** | **ON** |
| **Full group path** | **OFF** |

4. Click **"Save"**

### 6.6 Verify Mappers

You should now have 4 mappers listed:
- email
- firstName
- lastName
- groups

---

## 7. Create Test User

### 7.1 Navigate to Users

1. In the left menu, click **"Users"**

2. Click the **"Add user"** button

### 7.2 Create User

Fill in the following:

| Field | Value |
|-------|-------|
| **Username** | `testuser` |
| **Email** | `testuser@example.com` |
| **Email verified** | **ON** (toggle switch) |
| **First name** | `Test` |
| **Last name** | `User` |

Click **"Create"**

### 7.3 Set Password

1. Click the **"Credentials"** tab

2. Click **"Set password"**

3. Enter:

| Field | Value |
|-------|-------|
| **Password** | `password123` |
| **Password confirmation** | `password123` |
| **Temporary** | **OFF** (important!) |

4. Click **"Save"**

5. Click **"Save password"** in the confirmation dialog

---

## 8. Get Keycloak Certificate

You need the Keycloak signing certificate to configure your IDP schema.

### 8.1 Navigate to Realm Settings

1. In the left menu, click **"Realm settings"**

2. Click the **"Keys"** tab

### 8.2 Find the Signing Certificate

1. Look for the row with:
   - **Algorithm:** RS256
   - **Use:** SIG

2. Click the **"Certificate"** button on that row (not "Public key")

### 8.3 Copy Certificate

A popup will display the certificate. Copy the entire text.

**Example certificate format:**
```
MIICrTCCAZUCBgGbsq41CTANBgkqhkiG9w0BAQsFADAaMRgwFgYDVQQDDA9jb21w
bGlhbmNldmF1bHQwHhcNMjYwMTEyMTQ0NjU5WhcNMzYwMTEyMTQ0ODM5WjAaMRgw
...
```

### 8.4 Store Certificate for Database Configuration

When adding to the database, wrap with BEGIN/END lines:

```
-----BEGIN CERTIFICATE-----
MIICrTCCAZUCBgGbsq41CTANBgkqhkiG9w0BAQsFADAaMRgwFgYDVQQDDA9jb21w
bGlhbmNldmF1bHQwHhcNMjYwMTEyMTQ0NjU5WhcNMzYwMTEyMTQ0ODM5WjAaMRgw
...
-----END CERTIFICATE-----
```

---

## 9. Test Keycloak

### 9.1 Test Login Flow

1. Open a **new browser tab** (or incognito/private window)

2. Go to:
   ```
   http://localhost:8180/realms/compliancevault/protocol/saml/clients/medguard-dms
   ```

3. You should see the Keycloak login page

4. Log in with:
   - **Username:** `testuser`
   - **Password:** `password123`

### 9.2 Expected Result

After login, Keycloak will attempt to redirect to:
```
http://localhost:8080/ords/r/compliancevault/medguard-dms/saml-acs
```

**If you get a 404 error** - this is expected! It means:
- ✅ Keycloak is working correctly
- ✅ User authentication succeeded
- ✅ SAML response was generated
- ❌ APEX page doesn't exist yet (next step)

### 9.3 View SAML Response (Optional)

To see the actual SAML response being sent:

1. Install a SAML tracer browser extension:
   - **Chrome:** "SAML DevTools extension"
   - **Firefox:** "SAML-tracer"

2. Enable the extension

3. Repeat the login test

4. View the SAML response in the extension panel

---

## 10. Docker Commands Reference

### Start Keycloak
```bash
docker start keycloak-dev
```

### Stop Keycloak
```bash
docker stop keycloak-dev
```

### View Keycloak Logs
```bash
docker logs -f keycloak-dev
```

### Check if Keycloak is Running
```bash
docker ps | grep keycloak
```

### Remove Keycloak Container (to start fresh)
```bash
docker rm -f keycloak-dev
```

### Restart Keycloak
```bash
docker restart keycloak-dev
```

---

## 11. Troubleshooting

### Keycloak Won't Start

**Check if port 8180 is in use:**
```bash
lsof -i :8180
```

**Check Docker logs:**
```bash
docker logs keycloak-dev
```

### Can't Access Admin Console

1. Wait 60 seconds after starting - Keycloak takes time to initialize
2. Verify container is running: `docker ps`
3. Try: `http://localhost:8180` (should redirect to admin)

### Login Page Doesn't Appear

1. Verify you're using the correct URL:
   ```
   http://localhost:8180/realms/compliancevault/protocol/saml/clients/medguard-dms
   ```

2. Verify the realm name is `compliancevault` (case-sensitive)

3. Verify the client ID is `medguard-dms`

### "Invalid Username or Password" Error

1. Verify user exists: Users → search for "testuser"
2. Reset password: Credentials tab → Set password
3. Ensure "Temporary" is OFF when setting password

### "Invalid Redirect URI" Error

1. Go to Clients → medguard-dms → Settings
2. Verify "Valid redirect URIs" includes `http://localhost:8080/*`
3. Save and try again

### User Not Found After Login

1. Verify attribute mappers are configured correctly
2. Check that email attribute is mapped
3. Verify "Email verified" is ON for the user

---

## Quick Reference Card

### URLs

| Purpose | URL |
|---------|-----|
| Keycloak Admin Console | http://localhost:8180/admin |
| Test SSO Login | http://localhost:8180/realms/compliancevault/protocol/saml/clients/medguard-dms |
| IdP Metadata | http://localhost:8180/realms/compliancevault/protocol/saml/descriptor |
| SAML SSO Endpoint | http://localhost:8180/realms/compliancevault/protocol/saml |

### Credentials

| User | Username | Password | Purpose |
|------|----------|----------|---------|
| Keycloak Admin | admin | admin | Manage Keycloak |
| Test User | testuser | password123 | Test SSO login |

### Configuration Values for IDP Schema

| Setting | Value |
|---------|-------|
| IdP Entity ID | `http://localhost:8180/realms/compliancevault` |
| SP Entity ID | `medguard-dms` |
| SSO URL | `http://localhost:8180/realms/compliancevault/protocol/saml` |
| ACS URL | `http://localhost:8080/ords/r/compliancevault/medguard-dms/saml-acs` |

---

## Next Steps

After completing this guide:

1. **Run the IDP schema configuration SQL** - configures the database with Keycloak settings

2. **Create the SAML ACS page in APEX** - receives and processes SAML responses

3. **Test end-to-end authentication** - verify complete SSO flow

---

*Document Version: 1.0*
*Last Updated: January 2026*

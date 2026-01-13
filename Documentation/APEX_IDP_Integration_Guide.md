# APEX Integration Guide: IDP Federated Authentication + MFA + SOC2

## Overview

This guide explains how to integrate the IDP (Identity Provider) schema with Oracle APEX for federated authentication, MFA, and automatic SOC2 compliance logging.

## Architecture Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           APEX APPLICATION                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐                   │
│  │  Page 101    │    │  Page 102    │    │  Page 1      │                   │
│  │  LOGIN       │───►│  MFA VERIFY  │───►│  HOME        │                   │
│  │              │    │  (if needed) │    │              │                   │
│  └──────────────┘    └──────────────┘    └──────────────┘                   │
│         │                   │                                                │
│         ▼                   ▼                                                │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │              APEX AUTHENTICATION SCHEME                              │    │
│  │              Type: Custom                                            │    │
│  │              Function: return IDP.fn_apex_authenticate               │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                              │                                               │
└──────────────────────────────┼───────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           DATABASE                                           │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────────────┐         ┌─────────────────────────────────────┐    │
│  │    IDP SCHEMA       │         │         DMS SCHEMA                  │    │
│  │                     │         │                                     │    │
│  │  federated_auth_pkg │────────►│  SOC2_COMPLIANCE_PKG                │    │
│  │  mfa_auth_pkg       │ Bridge  │  SEC_AUTHENTICATION_LOG             │    │
│  │  idp_dms_bridge_pkg │────────►│  SEC_ACTIVE_SESSIONS                │    │
│  │                     │         │  SEC_INCIDENTS                      │    │
│  └─────────────────────┘         └─────────────────────────────────────┘    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Authentication Flow

```
User enters credentials
        │
        ▼
┌───────────────────┐
│ APEX Login Page   │
│ (Page 101)        │
└─────────┬─────────┘
          │
          ▼
┌───────────────────────────────────┐
│ Custom Auth Function              │
│ IDP.fn_apex_authenticate()        │
│   │                               │
│   ├─► Determine provider (NATIVE, │
│   │   SAML, LDAP, etc.)           │
│   │                               │
│   ├─► Call federated_auth_pkg     │
│   │   .authenticate()             │
│   │                               │
│   ├─► Bridge logs to DMS SOC2     │◄── Automatic!
│   │                               │
│   └─► Check if MFA required       │
└─────────┬─────────────────────────┘
          │
          ▼
    ┌─────┴─────┐
    │MFA needed?│
    └─────┬─────┘
          │
    ┌─────┴─────┐
    │           │
   YES          NO
    │           │
    ▼           ▼
┌─────────┐  ┌─────────┐
│Page 102 │  │ Page 1  │
│MFA Code │  │ Home    │
└────┬────┘  └─────────┘
     │
     ▼
┌───────────────────────────────────┐
│ MFA Verification                  │
│ IDP.mfa_auth_pkg.verify_totp()    │
│   │                               │
│   └─► Bridge logs to DMS SOC2     │◄── Automatic!
└─────────┬─────────────────────────┘
          │
          ▼
┌───────────────────┐
│ Page 1 - Home     │
└───────────────────┘
```

---

## Implementation Steps

### Step 1: Create the APEX Authentication Function

This function lives in the IDP schema and is called by APEX:

```sql
CREATE OR REPLACE FUNCTION IDP.fn_apex_authenticate
    (p_username     IN VARCHAR2
    ,p_password     IN VARCHAR2
    )
RETURN BOOLEAN
AS
    lt_result       IDP.federated_auth_pkg.t_auth_result;
    ln_tenant_id    NUMBER := 1;  -- Or get from application item
    lv_client_ip    VARCHAR2(50);
    lv_user_agent   VARCHAR2(1000);
    lb_mfa_required BOOLEAN := FALSE;
BEGIN
    -- Get client info from APEX
    lv_client_ip := OWA_UTIL.GET_CGI_ENV('REMOTE_ADDR');
    lv_user_agent := OWA_UTIL.GET_CGI_ENV('HTTP_USER_AGENT');
    
    -- Call federated authentication
    -- This automatically logs to both IDP and DMS (via bridge)
    lt_result := IDP.federated_auth_pkg.authenticate(
        pn_tenant_id    => ln_tenant_id
       ,pv_username     => p_username
       ,pv_password     => p_password
       ,pv_client_ip    => lv_client_ip
       ,pv_user_agent   => lv_user_agent
    );
    
    IF NOT lt_result.is_authenticated THEN
        -- Authentication failed - already logged via bridge
        RETURN FALSE;
    END IF;
    
    -- Check if MFA is required
    lb_mfa_required := IDP.mfa_auth_pkg.is_mfa_required(
        pn_tenant_id    => ln_tenant_id
       ,pv_user_id      => lt_result.user_id
    );
    
    IF lb_mfa_required THEN
        -- Store user info in APEX session for MFA page
        APEX_UTIL.SET_SESSION_STATE('G_PENDING_USER', lt_result.user_id);
        APEX_UTIL.SET_SESSION_STATE('G_MFA_REQUIRED', 'Y');
        APEX_UTIL.SET_SESSION_STATE('G_IDP_SESSION_TOKEN', lt_result.session_token);
        
        -- Don't fully authenticate yet - redirect to MFA page
        -- Return TRUE to allow session, but use post-auth to redirect
        RETURN TRUE;
    END IF;
    
    -- No MFA required - full authentication
    APEX_UTIL.SET_SESSION_STATE('G_MFA_REQUIRED', 'N');
    APEX_UTIL.SET_SESSION_STATE('G_IDP_SESSION_TOKEN', lt_result.session_token);
    
    RETURN TRUE;
    
EXCEPTION
    WHEN OTHERS THEN
        -- Log error but don't expose details
        RETURN FALSE;
END fn_apex_authenticate;
/

GRANT EXECUTE ON IDP.fn_apex_authenticate TO APEX_PUBLIC_USER;
GRANT EXECUTE ON IDP.fn_apex_authenticate TO DMS;
```

### Step 2: Configure APEX Authentication Scheme

1. Go to **Shared Components** → **Authentication Schemes**
2. Click **Create**
3. Select **Based on a pre-configured scheme from the gallery**
4. Choose **Custom**
5. Configure:

| Setting | Value |
|---------|-------|
| Name | `IDP Federated Authentication` |
| Scheme Type | `Custom` |
| Authentication Function Name | `return IDP.fn_apex_authenticate` |
| Session Not Valid | (your invalid session page) |
| Switch in Session | `Disabled` |

6. Make it the **Current** scheme

### Step 3: Create Application Items

Go to **Shared Components** → **Application Items** and create:

| Item Name | Scope | Session State Protection |
|-----------|-------|-------------------------|
| G_TENANT_ID | Application | Checksum Required |
| G_PENDING_USER | Application | Checksum Required |
| G_MFA_REQUIRED | Application | Checksum Required |
| G_IDP_SESSION_TOKEN | Application | Checksum Required |
| G_MFA_VERIFIED | Application | Checksum Required |

### Step 4: Create Post-Authentication Process

**Shared Components** → **Application Processes** → **Create**

| Setting | Value |
|---------|-------|
| Name | `Check MFA Redirect` |
| Point | `After Authentication` |
| Condition | `Always` |

**PL/SQL Code:**
```sql
BEGIN
    -- If MFA is required and not yet verified, redirect to MFA page
    IF :G_MFA_REQUIRED = 'Y' AND NVL(:G_MFA_VERIFIED, 'N') = 'N' THEN
        -- Redirect to MFA verification page
        APEX_UTIL.REDIRECT_URL(
            p_url => APEX_PAGE.GET_URL(p_page => 102)  -- MFA page
        );
    END IF;
END;
```

### Step 5: Create MFA Verification Page (Page 102)

#### Page Properties
- Page Mode: Normal
- Authentication: Page Is Public (we handle auth manually)

#### Page Items

| Item | Type | Label |
|------|------|-------|
| P102_TOTP_CODE | Text Field | Enter 6-digit code |
| P102_REMEMBER_DEVICE | Checkbox | Trust this device for 30 days |
| P102_ERROR_MSG | Display Only | (for error messages) |

#### Page Process: Verify MFA Code

| Setting | Value |
|---------|-------|
| Name | `Verify MFA Code` |
| Type | `PL/SQL Code` |
| When Button Pressed | `VERIFY` |

```sql
DECLARE
    lb_valid        BOOLEAN;
    lv_device_token VARCHAR2(256);
    ln_tenant_id    NUMBER := NVL(:G_TENANT_ID, 1);
    lv_client_ip    VARCHAR2(50);
BEGIN
    lv_client_ip := OWA_UTIL.GET_CGI_ENV('REMOTE_ADDR');
    
    -- Verify TOTP code
    -- This automatically logs to DMS SOC2 via bridge!
    lb_valid := IDP.mfa_auth_pkg.verify_totp(
        pn_tenant_id    => ln_tenant_id
       ,pv_user_id      => :G_PENDING_USER
       ,pv_totp_code    => :P102_TOTP_CODE
       ,pv_client_ip    => lv_client_ip
       ,pv_session_id   => :APP_SESSION
    );
    
    IF NOT lb_valid THEN
        -- Show error
        :P102_ERROR_MSG := 'Invalid code. Please try again.';
        RETURN;
    END IF;
    
    -- MFA verified!
    :G_MFA_VERIFIED := 'Y';
    
    -- Handle "Remember this device" checkbox
    IF :P102_REMEMBER_DEVICE = 'Y' THEN
        lb_valid := IDP.mfa_auth_pkg.trust_device(
            pn_tenant_id    => ln_tenant_id
           ,pv_user_id      => :G_PENDING_USER
           ,pv_device_name  => 'Web Browser'
           ,pv_user_agent   => OWA_UTIL.GET_CGI_ENV('HTTP_USER_AGENT')
           ,pv_client_ip    => lv_client_ip
           ,pv_device_token => lv_device_token
        );
        
        -- Store device token in cookie for future logins
        IF lv_device_token IS NOT NULL THEN
            OWA_COOKIE.SEND(
                name    => 'MFA_DEVICE_TOKEN'
               ,value   => lv_device_token
               ,expires => SYSDATE + 30
               ,path    => '/'
               ,secure  => TRUE
            );
        END IF;
    END IF;
    
    -- Redirect to home page
    APEX_UTIL.REDIRECT_URL(
        p_url => APEX_PAGE.GET_URL(p_page => 1)
    );
END;
```

#### Button: Use Backup Code

Add a link/button for users who lost their authenticator:

```sql
-- Process for backup code verification
DECLARE
    lb_valid    BOOLEAN;
BEGIN
    lb_valid := IDP.mfa_auth_pkg.verify_backup_code(
        pn_tenant_id    => NVL(:G_TENANT_ID, 1)
       ,pv_user_id      => :G_PENDING_USER
       ,pv_backup_code  => :P102_BACKUP_CODE
       ,pv_client_ip    => OWA_UTIL.GET_CGI_ENV('REMOTE_ADDR')
    );
    
    IF lb_valid THEN
        :G_MFA_VERIFIED := 'Y';
        APEX_UTIL.REDIRECT_URL(p_url => APEX_PAGE.GET_URL(p_page => 1));
    ELSE
        :P102_ERROR_MSG := 'Invalid backup code.';
    END IF;
END;
```

---

## SAML/SSO Integration

For SAML authentication, you need additional pages:

### Page 103: SSO Redirect (Public Page)

This page initiates SAML authentication:

```sql
-- On Page Load - Before Header process
DECLARE
    lv_saml_url     VARCHAR2(4000);
    ln_provider_id  NUMBER;
BEGIN
    -- Get the default SAML provider
    ln_provider_id := IDP.federated_auth_pkg.get_default_provider(
        pn_tenant_id => NVL(:G_TENANT_ID, 1)
    );
    
    -- Generate SAML request URL
    lv_saml_url := IDP.federated_auth_pkg.get_saml_sso_url(
        pn_tenant_id    => NVL(:G_TENANT_ID, 1)
       ,pn_aip_id       => ln_provider_id
       ,pv_relay_state  => :APP_SESSION  -- Return session ID
    );
    
    -- Redirect to Identity Provider
    APEX_UTIL.REDIRECT_URL(p_url => lv_saml_url);
END;
```

### Page 104: SAML Callback (Public Page)

This page receives the SAML response from the Identity Provider:

```sql
-- On Page Load process
DECLARE
    lt_result       IDP.federated_auth_pkg.t_auth_result;
    lv_saml_response CLOB;
BEGIN
    -- Get SAML response from POST
    lv_saml_response := APEX_APPLICATION.G_X01;  -- Or from appropriate source
    
    -- Process SAML response
    lt_result := IDP.federated_auth_pkg.process_saml_response(
        pn_tenant_id        => NVL(:G_TENANT_ID, 1)
       ,pn_aip_id           => :P104_PROVIDER_ID
       ,pv_saml_response    => lv_saml_response
       ,pv_client_ip        => OWA_UTIL.GET_CGI_ENV('REMOTE_ADDR')
    );
    
    IF lt_result.is_authenticated THEN
        -- Create APEX session
        APEX_AUTHENTICATION.LOGIN(
            p_username => lt_result.username
           ,p_password => NULL  -- No password for SSO
        );
        
        -- Check MFA
        IF lt_result.mfa_required THEN
            :G_MFA_REQUIRED := 'Y';
            :G_PENDING_USER := lt_result.user_id;
            APEX_UTIL.REDIRECT_URL(p_url => APEX_PAGE.GET_URL(p_page => 102));
        ELSE
            APEX_UTIL.REDIRECT_URL(p_url => APEX_PAGE.GET_URL(p_page => 1));
        END IF;
    ELSE
        -- Auth failed
        :P104_ERROR := lt_result.error_message;
    END IF;
END;
```

---

## Login Page Enhancement (Page 101)

Modify your login page to support multiple auth methods:

### Region: Login Options

```html
<!-- Standard login form -->
<div class="login-form">
    <!-- Username/Password fields -->
</div>

<!-- SSO Options -->
<div class="sso-options">
    <h4>Or sign in with:</h4>
    <a href="f?p=&APP_ID.:103:&SESSION." class="sso-button saml">
        <img src="#IMAGE_PREFIX#sso/corporate-sso.png" />
        Corporate SSO
    </a>
</div>
```

### Check Trusted Device on Login

Add this to the authentication function or post-auth process:

```sql
-- Check if device is trusted (skip MFA)
DECLARE
    lb_trusted  BOOLEAN;
    lv_token    VARCHAR2(256);
BEGIN
    -- Get device token from cookie
    lv_token := OWA_COOKIE.GET('MFA_DEVICE_TOKEN').vals(1);
    
    IF lv_token IS NOT NULL THEN
        lb_trusted := IDP.mfa_auth_pkg.is_device_trusted(
            pn_tenant_id    => NVL(:G_TENANT_ID, 1)
           ,pv_user_id      => :APP_USER
           ,pv_device_token => lv_token
        );
        
        IF lb_trusted THEN
            -- Skip MFA
            :G_MFA_REQUIRED := 'N';
            :G_MFA_VERIFIED := 'Y';
        END IF;
    END IF;
END;
```

---

## Session Timeout Handling

### Application Process: Session Keepalive

**Shared Components** → **Application Processes**

| Setting | Value |
|---------|-------|
| Name | `Refresh IDP Session` |
| Point | `On Load: Before Header` |
| Condition | `Every 5 minutes` |

```sql
BEGIN
    IF :G_IDP_SESSION_TOKEN IS NOT NULL THEN
        IDP.federated_auth_pkg.refresh_session(
            pn_tenant_id        => NVL(:G_TENANT_ID, 1)
           ,pv_session_token    => :G_IDP_SESSION_TOKEN
           ,pn_extension_seconds => 1800  -- 30 minutes
        );
    END IF;
END;
```

### Logout Process

**Page 0 (Global Page)** or **Logout URL**:

```sql
BEGIN
    -- Invalidate IDP session (logs to SOC2 automatically)
    IF :G_IDP_SESSION_TOKEN IS NOT NULL THEN
        IDP.federated_auth_pkg.invalidate_session(
            pn_tenant_id    => NVL(:G_TENANT_ID, 1)
           ,pv_session_token => :G_IDP_SESSION_TOKEN
           ,pv_reason       => 'USER_LOGOUT'
        );
    END IF;
    
    -- Clear APEX session
    APEX_AUTHENTICATION.LOGOUT(
        p_this_app => TRUE
    );
END;
```

---

## What Happens Automatically (SOC2 Bridge)

Once you've set up the integration, these events are **automatically logged to DMS SOC2 tables**:

| User Action | IDP Function Called | Auto-Logged To |
|-------------|---------------------|----------------|
| Login attempt | `federated_auth_pkg.authenticate()` | AUTH_FEDERATION_LOG + SEC_AUTHENTICATION_LOG |
| Login success | `federated_auth_pkg.authenticate()` | Both logs + session created |
| Login failure | `federated_auth_pkg.authenticate()` | Both logs + failure reason |
| MFA verification | `mfa_auth_pkg.verify_totp()` | AUTH_MFA_CHALLENGES + SEC_AUTHENTICATION_LOG |
| Backup code used | `mfa_auth_pkg.verify_backup_code()` | Both + alert if codes low |
| Session refresh | `federated_auth_pkg.refresh_session()` | Session activity |
| Logout | `federated_auth_pkg.invalidate_session()` | Session terminated in both |
| Brute force (10+ failures) | Automatic detection | SEC_INCIDENTS |

**You don't need to add any additional logging code!** The bridge handles it all.

---

## Verification Query

To verify everything is working, run:

```sql
-- Check recent auth events from both systems
SELECT source_system
      ,username
      ,auth_result
      ,mfa_method
      ,event_timestamp
      ,ip_address
  FROM DMS.UNIFIED_AUTH_LOG_VW
 WHERE event_timestamp > SYSTIMESTAMP - INTERVAL '1' HOUR
 ORDER BY event_timestamp DESC;

-- Check active sessions
SELECT source_system
      ,user_id
      ,session_start
      ,last_activity
      ,is_active
  FROM DMS.UNIFIED_ACTIVE_SESSIONS_VW
 WHERE is_active = 'Y';

-- Check MFA compliance
SELECT * FROM DMS.SOC2_MFA_COMPLIANCE_VW;
```

---

## Summary

| Component | Purpose |
|-----------|---------|
| `IDP.fn_apex_authenticate` | APEX calls this to authenticate users |
| `IDP.federated_auth_pkg` | Handles all auth methods (Native, SAML, LDAP) |
| `IDP.mfa_auth_pkg` | Handles MFA enrollment and verification |
| `IDP.idp_dms_bridge_pkg` | **Automatically** logs all events to DMS SOC2 |
| `DMS.SOC2_COMPLIANCE_PKG` | Receives bridged events |
| `DMS.UNIFIED_*_VW` | Unified views for compliance reporting |

The key insight is: **once the bridge is in place, you just call IDP functions normally, and SOC2 logging happens automatically**.

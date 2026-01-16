# MedGuard-DMS APEX Authentication Setup

## Complete Guide for SAML SSO with Keycloak

This guide configures your MedGuard-DMS APEX application to use the IDP schema's federated authentication with Keycloak SAML.

---

## Part 1: Authentication Scheme Configuration

### Step 1: Edit the SAML SSO Authentication Scheme

1. Go to **Shared Components** → **Authentication Schemes**
2. Click on **"SAML SSO Authentication"**

### Step 2: Configure Source Settings

Under the **"Source"** section:

| Property | Value |
|----------|-------|
| **Sentry Function Name** | `IDP.federated_auth_pkg.apex_session_sentry` |

**Note:** If the function doesn't exist yet, use this for now:
```
return true;
```

### Step 3: Configure Login Processing

Under the **"Login Processing"** section:

| Property | Value |
|----------|-------|
| **Authentication Function Name** | `return IDP.federated_auth_pkg.apex_authenticate(pn_tenant_id => NVL(TO_NUMBER(V('G_TENANT_ID')),1), pv_username => :P9999_USERNAME, pv_password => :P9999_PASSWORD);` |
| **Post-Authentication Procedure Name** | (leave blank) |

### Step 4: Configure Session Management

Under the **"Session Not Valid"** section:

| Property | Value |
|----------|-------|
| **Session Not Valid URL** | `f?p=&APP_ID.:LOGIN:&SESSION.` |

### Step 5: Configure Logout

Under the **"Logout URL"** section:

| Property | Value |
|----------|-------|
| **Logout URL** | `f?p=&APP_ID.:LOGIN:&SESSION.::&DEBUG.::` |

Click **"Apply Changes"**

### Step 6: Make It Current

1. Click **"Set as Current"** button (if not already current)

---

## Part 2: Application Items

### Create Required Application Items

Go to **Shared Components** → **Application Items** and create:

| Name | Scope | Session State Protection |
|------|-------|--------------------------|
| G_TENANT_ID | Application | Restricted - May not be set from browser |
| G_USER_ID | Application | Restricted - May not be set from browser |
| G_USER_EMAIL | Application | Restricted - May not be set from browser |
| G_USER_DISPLAY_NAME | Application | Unrestricted |
| G_USER_ROLES | Application | Restricted - May not be set from browser |
| G_AUTH_PROVIDER | Application | Unrestricted |
| G_IDP_SESSION_TOKEN | Application | Restricted - May not be set from browser |
| G_MFA_REQUIRED | Application | Restricted - May not be set from browser |
| G_MFA_VERIFIED | Application | Restricted - May not be set from browser |
| G_PENDING_USER | Application | Restricted - May not be set from browser |

---

## Part 3: Application Process - Initialize Tenant

### Create On New Session Process

1. Go to **Shared Components** → **Application Processes**
2. Click **"Create"**
3. Configure:

| Property | Value |
|----------|-------|
| **Name** | Initialize Session |
| **Point** | On New Session (Before Header) |
| **PL/SQL Code** | (see below) |

```sql
BEGIN
    -- Set default tenant (adjust for multi-tenant scenarios)
    :G_TENANT_ID := 1;
    
    -- Initialize MFA flags
    :G_MFA_REQUIRED := 'N';
    :G_MFA_VERIFIED := 'N';
END;
```

Click **"Create Process"**

---

## Part 4: Update SAML ACS Page (Page 9998)

### Update the Process SAML Response Process

1. Go to **Page 9998: SAML ACS**
2. In the **Processing** tab, click on **"Process SAML Response"**
3. Replace the PL/SQL Code with:

```sql
DECLARE
    lv_saml_response    CLOB;
    lv_relay_state      VARCHAR2(4000);
    lt_result           IDP.federated_auth_pkg.t_auth_result;
    ln_tenant_id        NUMBER;
    lv_client_ip        VARCHAR2(50);
    lv_user_agent       VARCHAR2(1000);
    lv_redirect_url     VARCHAR2(4000);
BEGIN
    -- ========================================================================
    -- Get SAML Response from POST
    -- ========================================================================
    -- Try multiple sources for the SAML response
    lv_saml_response := :P9998_SAMLRESPONSE;
    
    IF lv_saml_response IS NULL THEN
        -- Try getting from request body
        BEGIN
            lv_saml_response := APEX_APPLICATION.G_X01;
        EXCEPTION
            WHEN OTHERS THEN NULL;
        END;
    END IF;
    
    -- Get RelayState
    lv_relay_state := :P9998_RELAYSTATE;
    
    -- Get client info
    lv_client_ip := OWA_UTIL.GET_CGI_ENV('REMOTE_ADDR');
    lv_user_agent := SUBSTR(OWA_UTIL.GET_CGI_ENV('HTTP_USER_AGENT'), 1, 1000);
    
    -- Log for debugging
    APEX_DEBUG.INFO('SAML ACS: Response length = %s', NVL(LENGTH(lv_saml_response), 0));
    APEX_DEBUG.INFO('SAML ACS: RelayState = %s', lv_relay_state);
    
    -- ========================================================================
    -- Validate SAML Response Present
    -- ========================================================================
    IF lv_saml_response IS NULL THEN
        APEX_DEBUG.ERROR('SAML ACS: No SAML response received');
        APEX_UTIL.REDIRECT_URL(
            p_url => APEX_PAGE.GET_URL(
                p_page => 'LOGIN'
               ,p_request => 'SAML_NO_RESPONSE'
            )
        );
        RETURN;
    END IF;
    
    -- ========================================================================
    -- Get Tenant ID
    -- ========================================================================
    ln_tenant_id := NVL(TO_NUMBER(V('G_TENANT_ID')), 1);
    
    -- ========================================================================
    -- Process SAML Response
    -- ========================================================================
    lt_result := IDP.federated_auth_pkg.authenticate(
        pn_tenant_id        => ln_tenant_id
       ,pv_username         => NULL  -- Will be extracted from SAML
       ,pv_password         => NULL
       ,pv_provider_code    => NULL  -- Auto-detect from SAML issuer
       ,pv_saml_response    => lv_saml_response
       ,pv_client_ip        => lv_client_ip
       ,pv_user_agent       => lv_user_agent
    );
    
    -- ========================================================================
    -- Handle Authentication Result
    -- ========================================================================
    IF lt_result.is_authenticated THEN
        -- Set APEX session state
        APEX_UTIL.SET_SESSION_STATE('G_USER_ID', lt_result.user_id);
        APEX_UTIL.SET_SESSION_STATE('G_USER_EMAIL', lt_result.email);
        APEX_UTIL.SET_SESSION_STATE('G_USER_DISPLAY_NAME', lt_result.display_name);
        APEX_UTIL.SET_SESSION_STATE('G_USER_ROLES', lt_result.roles);
        APEX_UTIL.SET_SESSION_STATE('G_AUTH_PROVIDER', lt_result.provider_name);
        APEX_UTIL.SET_SESSION_STATE('G_IDP_SESSION_TOKEN', lt_result.session_token);
        
        -- Handle MFA requirement
        IF lt_result.mfa_required THEN
            APEX_UTIL.SET_SESSION_STATE('G_MFA_REQUIRED', 'Y');
            APEX_UTIL.SET_SESSION_STATE('G_MFA_VERIFIED', 'N');
            APEX_UTIL.SET_SESSION_STATE('G_PENDING_USER', lt_result.user_id);
        ELSE
            APEX_UTIL.SET_SESSION_STATE('G_MFA_REQUIRED', 'N');
            APEX_UTIL.SET_SESSION_STATE('G_MFA_VERIFIED', 'Y');
        END IF;
        
        -- Log the user in to APEX
        APEX_AUTHENTICATION.LOGIN(
            p_username => lt_result.user_id
           ,p_password => NULL
        );
        
        -- Determine redirect URL
        IF lt_result.mfa_required THEN
            -- Redirect to MFA verification page
            lv_redirect_url := APEX_PAGE.GET_URL(p_page => 'MFA-VERIFY');
        ELSIF lv_relay_state IS NOT NULL AND INSTR(lv_relay_state, 'f?p=') > 0 THEN
            -- Redirect to original requested page
            lv_redirect_url := lv_relay_state;
        ELSE
            -- Default to home page
            lv_redirect_url := APEX_PAGE.GET_URL(p_page => 1);
        END IF;
        
        APEX_DEBUG.INFO('SAML ACS: Authentication successful, redirecting to %s', lv_redirect_url);
        APEX_UTIL.REDIRECT_URL(p_url => lv_redirect_url);
        
    ELSE
        -- Authentication failed
        APEX_DEBUG.ERROR('SAML ACS: Authentication failed - %s: %s', 
            lt_result.error_code, lt_result.error_message);
        
        APEX_UTIL.SET_SESSION_STATE('LOGIN_MESSAGE', 
            NVL(lt_result.error_message, 'SSO authentication failed'));
        
        APEX_UTIL.REDIRECT_URL(
            p_url => APEX_PAGE.GET_URL(
                p_page => 'LOGIN'
               ,p_request => 'SAML_ERROR:' || NVL(lt_result.error_code, 'UNKNOWN')
            )
        );
    END IF;
    
EXCEPTION
    WHEN OTHERS THEN
        APEX_DEBUG.ERROR('SAML ACS: Exception - %s', SQLERRM);
        APEX_UTIL.REDIRECT_URL(
            p_url => APEX_PAGE.GET_URL(
                p_page => 'LOGIN'
               ,p_request => 'SAML_EXCEPTION'
            )
        );
END;
```

4. Click **"Save"**

---

## Part 5: Login Page Updates

### Add "Sign in with SSO" Button

On your Login page, add a button to initiate SSO:

1. Go to your Login page
2. Add a **Button** with:

| Property | Value |
|----------|-------|
| **Button Name** | BTN_SSO_LOGIN |
| **Label** | Sign in with SSO |
| **Action** | Redirect to URL |
| **URL** | `http://localhost:8180/realms/compliancevault/protocol/saml/clients/medguard-dms` |

**For production**, create a dynamic action or process that calls:
```sql
DECLARE
    lv_sso_url VARCHAR2(2000);
BEGIN
    SELECT asg.sso_url || '/clients/' || asg.sp_entity_id
      INTO lv_sso_url
      FROM IDP.AUTH_SAML_CONFIG asg
          ,IDP.AUTH_IDENTITY_PROVIDERS aip
     WHERE asg.asg_aip_id = aip.aip_id
       AND aip.tenant_id = :G_TENANT_ID
       AND aip.is_default = 'Y'
       AND aip.is_active = 'Y';
    
    APEX_UTIL.REDIRECT_URL(p_url => lv_sso_url);
END;
```

---

## Part 6: Testing

### Test 1: IdP-Initiated Login

1. Open: `http://localhost:8180/realms/compliancevault/protocol/saml/clients/medguard-dms`
2. Log in with: `testuser` / `password123`
3. You should be redirected to your DMS home page, logged in

### Test 2: SP-Initiated Login

1. Go to your DMS login page
2. Click "Sign in with SSO"
3. Log in at Keycloak
4. You should be redirected back to DMS, logged in

### Verify Login

After successful login, check:
- `&APP_USER.` should show `testuser` (or email)
- `&G_USER_EMAIL.` should show `testuser@example.com`
- `&G_AUTH_PROVIDER.` should show `Keycloak SSO`

---

## Troubleshooting

### "Page not found" after Keycloak login
- Verify page alias is `saml-acs` (case-sensitive)
- Verify page 9998 is set to "Page Is Public"

### "Authentication failed" 
- Check APEX Debug mode for detailed error
- Verify IDP schema packages are installed
- Verify Keycloak certificate is correct in AUTH_SAML_CONFIG

### Session not persisting
- Verify APEX_AUTHENTICATION.LOGIN is being called
- Check authentication scheme is set as current

### MFA keeps redirecting
- Check G_MFA_REQUIRED and G_MFA_VERIFIED values
- Verify MFA page exists if MFA is enabled

---

## Summary

| Component | Purpose |
|-----------|---------|
| Authentication Scheme | Validates sessions, handles login |
| Page 9998 (saml-acs) | Receives SAML response from Keycloak |
| Application Items | Store session state (user info, tokens) |
| Application Process | Initialize tenant on new session |
| Login Page Button | Initiates SSO flow |
| IDP Schema | Database layer for auth processing |

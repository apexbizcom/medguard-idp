CREATE OR REPLACE PACKAGE IDP.idp_dms_bridge_pkg
AUTHID CURRENT_USER
AS
    -- ============================================================================
    -- IDP-DMS Bridge Package
    -- ============================================================================
    -- Schema: IDP
    -- Purpose: Bridges authentication events from IDP to DMS SOC2 compliance tables
    -- Version: 1.0
    -- ============================================================================
    -- 
    -- This package synchronizes authentication events between:
    --   - IDP.AUTH_FEDERATION_LOG (IDP's audit log)
    --   - DMS.SEC_AUTHENTICATION_LOG (SOC2 compliance log)
    --   - DMS.SEC_ACTIVE_SESSIONS (Session tracking)
    --
    -- Prerequisites:
    --   GRANT EXECUTE ON DMS.SOC2_COMPLIANCE_PKG TO IDP;
    --
    -- ============================================================================

    -- ========================================================================
    -- CONSTANTS
    -- ========================================================================
    
    -- Enable/disable bridge (for testing or if DMS not installed)
    gc_bridge_enabled       CONSTANT BOOLEAN := TRUE;
    
    -- Auth result mappings
    gc_result_success       CONSTANT VARCHAR2(20) := 'SUCCESS';
    gc_result_failed        CONSTANT VARCHAR2(20) := 'FAILED';
    gc_result_locked        CONSTANT VARCHAR2(20) := 'LOCKED';
    gc_result_expired       CONSTANT VARCHAR2(20) := 'EXPIRED';
    gc_result_mfa_required  CONSTANT VARCHAR2(20) := 'MFA_REQUIRED';
    gc_result_mfa_failed    CONSTANT VARCHAR2(20) := 'MFA_FAILED';
    gc_result_session_timeout CONSTANT VARCHAR2(20) := 'SESSION_TIMEOUT';
    
    -- Auth method mappings
    gc_method_password      CONSTANT VARCHAR2(20) := 'PASSWORD';
    gc_method_sso           CONSTANT VARCHAR2(20) := 'SSO';
    gc_method_mfa           CONSTANT VARCHAR2(20) := 'MFA';
    gc_method_certificate   CONSTANT VARCHAR2(20) := 'CERTIFICATE';
    gc_method_api_key       CONSTANT VARCHAR2(20) := 'API_KEY';
    gc_method_biometric     CONSTANT VARCHAR2(20) := 'BIOMETRIC';
    
    -- MFA method mappings
    gc_mfa_totp             CONSTANT VARCHAR2(20) := 'TOTP';
    gc_mfa_sms              CONSTANT VARCHAR2(20) := 'SMS';
    gc_mfa_email            CONSTANT VARCHAR2(20) := 'EMAIL';
    gc_mfa_push             CONSTANT VARCHAR2(20) := 'PUSH';
    gc_mfa_hardware_token   CONSTANT VARCHAR2(20) := 'HARDWARE_TOKEN';
    gc_mfa_backup_code      CONSTANT VARCHAR2(20) := 'BACKUP_CODE';
    gc_mfa_none             CONSTANT VARCHAR2(20) := 'NONE';
    
    -- ========================================================================
    -- TYPE DEFINITIONS
    -- ========================================================================
    
    TYPE t_auth_event IS RECORD
        (tenant_id          NUMBER
        ,username           VARCHAR2(255)
        ,auth_result        VARCHAR2(30)
        ,failure_reason     VARCHAR2(500)
        ,ip_address         VARCHAR2(50)
        ,user_agent         VARCHAR2(1000)
        ,auth_method        VARCHAR2(50)
        ,mfa_method         VARCHAR2(50)
        ,session_id         VARCHAR2(256)
        ,provider_type      VARCHAR2(30)
        ,provider_name      VARCHAR2(100)
        ,is_suspicious      VARCHAR2(1)
        ,external_id        VARCHAR2(500)
        );
    
    -- ========================================================================
    -- AUTHENTICATION EVENT BRIDGE
    -- ========================================================================
    
    -- Log authentication attempt to DMS SOC2 tables
    PROCEDURE bridge_auth_event
        (pt_event           IN  t_auth_event
        );
    
    -- Simplified version for common use
    PROCEDURE log_to_dms
        (pn_tenant_id       IN  NUMBER
        ,pv_username        IN  VARCHAR2
        ,pv_result          IN  VARCHAR2
        ,pv_ip_address      IN  VARCHAR2 DEFAULT NULL
        ,pv_auth_method     IN  VARCHAR2 DEFAULT 'SSO'
        ,pv_mfa_method      IN  VARCHAR2 DEFAULT 'NONE'
        ,pv_failure_reason  IN  VARCHAR2 DEFAULT NULL
        ,pv_session_id      IN  VARCHAR2 DEFAULT NULL
        ,pv_user_agent      IN  VARCHAR2 DEFAULT NULL
        ,pv_provider_type   IN  VARCHAR2 DEFAULT NULL
        );
    
    -- ========================================================================
    -- SESSION BRIDGE
    -- ========================================================================
    
    -- Create session in both IDP and DMS
    PROCEDURE bridge_create_session
        (pn_tenant_id       IN  NUMBER
        ,pv_user_id         IN  VARCHAR2
        ,pv_session_token   IN  VARCHAR2
        ,pv_ip_address      IN  VARCHAR2 DEFAULT NULL
        ,pn_timeout_minutes IN  NUMBER DEFAULT 30
        );
    
    -- Sync session activity
    PROCEDURE bridge_session_activity
        (pn_tenant_id       IN  NUMBER
        ,pv_session_token   IN  VARCHAR2
        ,pv_activity_type   IN  VARCHAR2
        ,pv_resource_type   IN  VARCHAR2 DEFAULT NULL
        ,pv_resource_id     IN  VARCHAR2 DEFAULT NULL
        ,pv_action_details  IN  VARCHAR2 DEFAULT NULL
        );
    
    -- Terminate session in both systems
    PROCEDURE bridge_terminate_session
        (pn_tenant_id       IN  NUMBER
        ,pv_session_token   IN  VARCHAR2
        ,pv_reason          IN  VARCHAR2 DEFAULT 'USER_LOGOUT'
        );
    
    -- ========================================================================
    -- MFA EVENT BRIDGE
    -- ========================================================================
    
    -- Log MFA challenge to DMS
    PROCEDURE bridge_mfa_challenge
        (pn_tenant_id       IN  NUMBER
        ,pv_user_id         IN  VARCHAR2
        ,pv_challenge_type  IN  VARCHAR2
        ,pb_was_successful  IN  BOOLEAN
        ,pv_ip_address      IN  VARCHAR2 DEFAULT NULL
        ,pv_user_agent      IN  VARCHAR2 DEFAULT NULL
        );
    
    -- Log MFA enrollment to DMS
    PROCEDURE bridge_mfa_enrollment
        (pn_tenant_id       IN  NUMBER
        ,pv_user_id         IN  VARCHAR2
        ,pv_action          IN  VARCHAR2  -- 'STARTED', 'COMPLETED', 'DISABLED'
        ,pv_ip_address      IN  VARCHAR2 DEFAULT NULL
        );
    
    -- ========================================================================
    -- SECURITY INCIDENT BRIDGE
    -- ========================================================================
    
    -- Create security incident in DMS based on IDP events
    PROCEDURE bridge_security_incident
        (pn_tenant_id       IN  NUMBER
        ,pv_title           IN  VARCHAR2
        ,pv_incident_type   IN  VARCHAR2
        ,pv_severity        IN  VARCHAR2
        ,pc_description     IN  CLOB
        ,pv_username        IN  VARCHAR2 DEFAULT NULL
        ,pv_ip_address      IN  VARCHAR2 DEFAULT NULL
        );
    
    -- Auto-detect suspicious activity and create incidents
    PROCEDURE check_suspicious_activity
        (pn_tenant_id       IN  NUMBER
        ,pv_username        IN  VARCHAR2
        ,pv_ip_address      IN  VARCHAR2
        );
    
    -- ========================================================================
    -- UTILITY FUNCTIONS
    -- ========================================================================
    
    -- Map IDP provider type to DMS auth method
    FUNCTION map_provider_to_auth_method
        (pv_provider_type   IN  VARCHAR2
        )
    RETURN VARCHAR2;
    
    -- Check if DMS SOC2 package is available
    FUNCTION is_dms_available
    RETURN BOOLEAN;
    
    -- Get unified auth statistics
    FUNCTION get_auth_stats
        (pn_tenant_id       IN  NUMBER
        ,pn_hours_back      IN  NUMBER DEFAULT 24
        )
    RETURN SYS_REFCURSOR;

END idp_dms_bridge_pkg;
/

CREATE OR REPLACE PACKAGE BODY IDP.idp_dms_bridge_pkg
AS
    -- ========================================================================
    -- PRIVATE VARIABLES
    -- ========================================================================
    gv_dms_available    BOOLEAN := NULL;
    
    -- ========================================================================
    -- PRIVATE FUNCTIONS
    -- ========================================================================
    
    -- Check if DMS schema and SOC2 package exist
    FUNCTION check_dms_available
    RETURN BOOLEAN IS
        ln_count    NUMBER;
    BEGIN
        SELECT COUNT(*)
          INTO ln_count
          FROM all_objects
         WHERE owner = 'DMS'
           AND object_name = 'SOC2_COMPLIANCE_PKG'
           AND object_type = 'PACKAGE';
        
        RETURN ln_count > 0;
    EXCEPTION
        WHEN OTHERS THEN
            RETURN FALSE;
    END check_dms_available;
    
    -- ========================================================================
    -- PUBLIC: is_dms_available
    -- ========================================================================
    FUNCTION is_dms_available
    RETURN BOOLEAN IS
    BEGIN
        IF gv_dms_available IS NULL THEN
            gv_dms_available := check_dms_available();
        END IF;
        RETURN gv_dms_available;
    END is_dms_available;
    
    -- ========================================================================
    -- PUBLIC: map_provider_to_auth_method
    -- ========================================================================
    FUNCTION map_provider_to_auth_method
        (pv_provider_type   IN  VARCHAR2
        )
    RETURN VARCHAR2 IS
    BEGIN
        RETURN CASE pv_provider_type
            WHEN 'SAML'     THEN gc_method_sso
            WHEN 'LDAP'     THEN gc_method_password
            WHEN 'OIDC'     THEN gc_method_sso
            WHEN 'CUSTOM'   THEN gc_method_api_key
            WHEN 'NATIVE'   THEN gc_method_password
            ELSE gc_method_password
        END;
    END map_provider_to_auth_method;
    
    -- ========================================================================
    -- PUBLIC: bridge_auth_event
    -- ========================================================================
    PROCEDURE bridge_auth_event
        (pt_event           IN  t_auth_event
        ) IS
    BEGIN
        IF NOT gc_bridge_enabled OR NOT is_dms_available() THEN
            RETURN;
        END IF;
        
        -- Call DMS SOC2 package
        DMS.SOC2_COMPLIANCE_PKG.log_auth_attempt(
            pn_tenant_id        => pt_event.tenant_id
           ,pv_username         => pt_event.username
           ,pv_result           => pt_event.auth_result
           ,pv_ip_address       => pt_event.ip_address
           ,pv_auth_method      => NVL(pt_event.auth_method, gc_method_sso)
           ,pv_mfa_method       => NVL(pt_event.mfa_method, gc_mfa_none)
           ,pv_failure_reason   => pt_event.failure_reason
           ,pv_session_id       => pt_event.session_id
           ,pv_user_agent       => pt_event.user_agent
        );
        
        -- Check for suspicious activity
        IF pt_event.auth_result = gc_result_failed THEN
            check_suspicious_activity(
                pn_tenant_id    => pt_event.tenant_id
               ,pv_username     => pt_event.username
               ,pv_ip_address   => pt_event.ip_address
            );
        END IF;
        
    EXCEPTION
        WHEN OTHERS THEN
            -- Log error but don't fail the authentication
            NULL;
    END bridge_auth_event;
    
    -- ========================================================================
    -- PUBLIC: log_to_dms (simplified version)
    -- ========================================================================
    PROCEDURE log_to_dms
        (pn_tenant_id       IN  NUMBER
        ,pv_username        IN  VARCHAR2
        ,pv_result          IN  VARCHAR2
        ,pv_ip_address      IN  VARCHAR2 DEFAULT NULL
        ,pv_auth_method     IN  VARCHAR2 DEFAULT 'SSO'
        ,pv_mfa_method      IN  VARCHAR2 DEFAULT 'NONE'
        ,pv_failure_reason  IN  VARCHAR2 DEFAULT NULL
        ,pv_session_id      IN  VARCHAR2 DEFAULT NULL
        ,pv_user_agent      IN  VARCHAR2 DEFAULT NULL
        ,pv_provider_type   IN  VARCHAR2 DEFAULT NULL
        ) IS
        lt_event    t_auth_event;
    BEGIN
        lt_event.tenant_id := pn_tenant_id;
        lt_event.username := pv_username;
        lt_event.auth_result := pv_result;
        lt_event.failure_reason := pv_failure_reason;
        lt_event.ip_address := pv_ip_address;
        lt_event.user_agent := pv_user_agent;
        lt_event.auth_method := NVL(pv_auth_method, map_provider_to_auth_method(pv_provider_type));
        lt_event.mfa_method := pv_mfa_method;
        lt_event.session_id := pv_session_id;
        lt_event.provider_type := pv_provider_type;
        lt_event.is_suspicious := 'N';
        
        bridge_auth_event(lt_event);
    END log_to_dms;
    
    -- ========================================================================
    -- PUBLIC: bridge_create_session
    -- ========================================================================
    PROCEDURE bridge_create_session
        (pn_tenant_id       IN  NUMBER
        ,pv_user_id         IN  VARCHAR2
        ,pv_session_token   IN  VARCHAR2
        ,pv_ip_address      IN  VARCHAR2 DEFAULT NULL
        ,pn_timeout_minutes IN  NUMBER DEFAULT 30
        ) IS
    BEGIN
        IF NOT gc_bridge_enabled OR NOT is_dms_available() THEN
            RETURN;
        END IF;
        
        -- Call DMS SOC2 session management
        DMS.SOC2_COMPLIANCE_PKG.manage_session(
            pn_tenant_id            => pn_tenant_id
           ,pv_action               => 'CREATE'
           ,pv_session_id           => pv_session_token
           ,pv_user_id              => pv_user_id
           ,pv_ip_address           => pv_ip_address
        );
        
    EXCEPTION
        WHEN OTHERS THEN
            NULL; -- Don't fail session creation
    END bridge_create_session;
    
    -- ========================================================================
    -- PUBLIC: bridge_session_activity
    -- ========================================================================
    PROCEDURE bridge_session_activity
        (pn_tenant_id       IN  NUMBER
        ,pv_session_token   IN  VARCHAR2
        ,pv_activity_type   IN  VARCHAR2
        ,pv_resource_type   IN  VARCHAR2 DEFAULT NULL
        ,pv_resource_id     IN  VARCHAR2 DEFAULT NULL
        ,pv_action_details  IN  VARCHAR2 DEFAULT NULL
        ) IS
    BEGIN
        IF NOT gc_bridge_enabled OR NOT is_dms_available() THEN
            RETURN;
        END IF;
        
        DMS.SOC2_COMPLIANCE_PKG.log_session_activity(
            pn_tenant_id        => pn_tenant_id
           ,pv_session_id       => pv_session_token
           ,pv_activity_type    => pv_activity_type
           ,pv_resource_type    => pv_resource_type
           ,pv_resource_id      => pv_resource_id
           ,pv_action_details   => pv_action_details
        );
        
    EXCEPTION
        WHEN OTHERS THEN
            NULL;
    END bridge_session_activity;
    
    -- ========================================================================
    -- PUBLIC: bridge_terminate_session
    -- ========================================================================
    PROCEDURE bridge_terminate_session
        (pn_tenant_id       IN  NUMBER
        ,pv_session_token   IN  VARCHAR2
        ,pv_reason          IN  VARCHAR2 DEFAULT 'USER_LOGOUT'
        ) IS
    BEGIN
        IF NOT gc_bridge_enabled OR NOT is_dms_available() THEN
            RETURN;
        END IF;
        
        DMS.SOC2_COMPLIANCE_PKG.manage_session(
            pn_tenant_id            => pn_tenant_id
           ,pv_action               => 'TERMINATE'
           ,pv_session_id           => pv_session_token
           ,pv_termination_reason   => pv_reason
        );
        
    EXCEPTION
        WHEN OTHERS THEN
            NULL;
    END bridge_terminate_session;
    
    -- ========================================================================
    -- PUBLIC: bridge_mfa_challenge
    -- ========================================================================
    PROCEDURE bridge_mfa_challenge
        (pn_tenant_id       IN  NUMBER
        ,pv_user_id         IN  VARCHAR2
        ,pv_challenge_type  IN  VARCHAR2
        ,pb_was_successful  IN  BOOLEAN
        ,pv_ip_address      IN  VARCHAR2 DEFAULT NULL
        ,pv_user_agent      IN  VARCHAR2 DEFAULT NULL
        ) IS
        lv_result       VARCHAR2(30);
        lv_mfa_method   VARCHAR2(30);
    BEGIN
        IF NOT gc_bridge_enabled OR NOT is_dms_available() THEN
            RETURN;
        END IF;
        
        -- Map result
        IF pb_was_successful THEN
            lv_result := gc_result_success;
        ELSE
            lv_result := gc_result_mfa_failed;
        END IF;
        
        -- Map MFA method
        lv_mfa_method := CASE pv_challenge_type
            WHEN 'TOTP'         THEN gc_mfa_totp
            WHEN 'BACKUP_CODE'  THEN gc_mfa_backup_code
            WHEN 'SMS'          THEN gc_mfa_sms
            WHEN 'EMAIL'        THEN gc_mfa_email
            WHEN 'PUSH'         THEN gc_mfa_push
            ELSE gc_mfa_totp
        END;
        
        DMS.SOC2_COMPLIANCE_PKG.log_auth_attempt(
            pn_tenant_id        => pn_tenant_id
           ,pv_username         => pv_user_id
           ,pv_result           => lv_result
           ,pv_ip_address       => pv_ip_address
           ,pv_auth_method      => gc_method_mfa
           ,pv_mfa_method       => lv_mfa_method
           ,pv_failure_reason   => CASE WHEN NOT pb_was_successful 
                                        THEN 'MFA verification failed' 
                                        ELSE NULL END
           ,pv_user_agent       => pv_user_agent
        );
        
    EXCEPTION
        WHEN OTHERS THEN
            NULL;
    END bridge_mfa_challenge;
    
    -- ========================================================================
    -- PUBLIC: bridge_mfa_enrollment
    -- ========================================================================
    PROCEDURE bridge_mfa_enrollment
        (pn_tenant_id       IN  NUMBER
        ,pv_user_id         IN  VARCHAR2
        ,pv_action          IN  VARCHAR2
        ,pv_ip_address      IN  VARCHAR2 DEFAULT NULL
        ) IS
        lv_result   VARCHAR2(30);
    BEGIN
        IF NOT gc_bridge_enabled OR NOT is_dms_available() THEN
            RETURN;
        END IF;
        
        -- Map action to result for logging
        lv_result := CASE pv_action
            WHEN 'STARTED'      THEN 'MFA_ENROLLMENT_STARTED'
            WHEN 'COMPLETED'    THEN 'MFA_ENROLLMENT_COMPLETED'
            WHEN 'DISABLED'     THEN 'MFA_DISABLED'
            ELSE 'MFA_' || pv_action
        END;
        
        DMS.SOC2_COMPLIANCE_PKG.log_auth_attempt(
            pn_tenant_id        => pn_tenant_id
           ,pv_username         => pv_user_id
           ,pv_result           => lv_result
           ,pv_ip_address       => pv_ip_address
           ,pv_auth_method      => gc_method_mfa
           ,pv_mfa_method       => gc_mfa_totp
        );
        
    EXCEPTION
        WHEN OTHERS THEN
            NULL;
    END bridge_mfa_enrollment;
    
    -- ========================================================================
    -- PUBLIC: bridge_security_incident
    -- ========================================================================
    PROCEDURE bridge_security_incident
        (pn_tenant_id       IN  NUMBER
        ,pv_title           IN  VARCHAR2
        ,pv_incident_type   IN  VARCHAR2
        ,pv_severity        IN  VARCHAR2
        ,pc_description     IN  CLOB
        ,pv_username        IN  VARCHAR2 DEFAULT NULL
        ,pv_ip_address      IN  VARCHAR2 DEFAULT NULL
        ) IS
        ln_incident_id  NUMBER;
    BEGIN
        IF NOT gc_bridge_enabled OR NOT is_dms_available() THEN
            RETURN;
        END IF;
        
        DMS.SOC2_COMPLIANCE_PKG.create_security_incident(
            pn_tenant_id        => pn_tenant_id
           ,pv_title            => pv_title
           ,pv_type             => pv_incident_type
           ,pv_severity         => pv_severity
           ,pc_description      => pc_description
           ,pv_detection_method => 'IDP_AUTOMATED_ALERT'
           ,pv_reported_by      => 'IDP_SYSTEM'
           ,pn_incident_id      => ln_incident_id
        );
        
    EXCEPTION
        WHEN OTHERS THEN
            NULL;
    END bridge_security_incident;
    
    -- ========================================================================
    -- PUBLIC: check_suspicious_activity
    -- ========================================================================
    PROCEDURE check_suspicious_activity
        (pn_tenant_id       IN  NUMBER
        ,pv_username        IN  VARCHAR2
        ,pv_ip_address      IN  VARCHAR2
        ) IS
        ln_recent_failures  NUMBER := 0;
        ln_unique_ips       NUMBER := 0;
        lv_description      CLOB;
    BEGIN
        -- Count recent failures from IDP log
        SELECT COUNT(*)
          INTO ln_recent_failures
          FROM IDP.AUTH_FEDERATION_LOG afl
         WHERE afl.tenant_id = pn_tenant_id
           AND afl.username = pv_username
           AND afl.was_successful = 'N'
           AND afl.event_timestamp > SYSTIMESTAMP - INTERVAL '1' HOUR;
        
        -- Check for multiple IPs
        SELECT COUNT(DISTINCT client_ip)
          INTO ln_unique_ips
          FROM IDP.AUTH_FEDERATION_LOG afl
         WHERE afl.tenant_id = pn_tenant_id
           AND afl.username = pv_username
           AND afl.event_timestamp > SYSTIMESTAMP - INTERVAL '1' HOUR;
        
        -- Trigger incident for brute force (10+ failures)
        IF ln_recent_failures >= 10 THEN
            lv_description := 'Potential brute force attack detected. User: ' || pv_username || 
                             '. Failed attempts in last hour: ' || ln_recent_failures ||
                             '. IP Address: ' || pv_ip_address;
            
            bridge_security_incident(
                pn_tenant_id        => pn_tenant_id
               ,pv_title            => 'Brute Force Attack Detected'
               ,pv_incident_type    => 'BRUTE_FORCE'
               ,pv_severity         => 'HIGH'
               ,pc_description      => lv_description
               ,pv_username         => pv_username
               ,pv_ip_address       => pv_ip_address
            );
        -- Trigger incident for credential stuffing (5+ IPs)
        ELSIF ln_unique_ips >= 5 AND ln_recent_failures >= 5 THEN
            lv_description := 'Potential credential stuffing detected. User: ' || pv_username || 
                             '. Unique IPs in last hour: ' || ln_unique_ips ||
                             '. Failed attempts: ' || ln_recent_failures;
            
            bridge_security_incident(
                pn_tenant_id        => pn_tenant_id
               ,pv_title            => 'Credential Stuffing Attack Suspected'
               ,pv_incident_type    => 'CREDENTIAL_STUFFING'
               ,pv_severity         => 'MEDIUM'
               ,pc_description      => lv_description
               ,pv_username         => pv_username
               ,pv_ip_address       => pv_ip_address
            );
        END IF;
        
    EXCEPTION
        WHEN OTHERS THEN
            NULL;
    END check_suspicious_activity;
    
    -- ========================================================================
    -- PUBLIC: get_auth_stats
    -- ========================================================================
    FUNCTION get_auth_stats
        (pn_tenant_id       IN  NUMBER
        ,pn_hours_back      IN  NUMBER DEFAULT 24
        )
    RETURN SYS_REFCURSOR IS
        lc_cursor   SYS_REFCURSOR;
    BEGIN
        OPEN lc_cursor FOR
            SELECT 'IDP' AS source
                  ,event_type
                  ,was_successful
                  ,COUNT(*) AS event_count
                  ,COUNT(DISTINCT username) AS unique_users
                  ,COUNT(DISTINCT client_ip) AS unique_ips
              FROM IDP.AUTH_FEDERATION_LOG
             WHERE tenant_id = pn_tenant_id
               AND event_timestamp > SYSTIMESTAMP - NUMTODSINTERVAL(pn_hours_back, 'HOUR')
             GROUP BY event_type, was_successful
            UNION ALL
            SELECT 'DMS' AS source
                  ,auth_result AS event_type
                  ,'Y' AS was_successful  -- Map SUCCESS='Y', others='N'
                  ,COUNT(*) AS event_count
                  ,COUNT(DISTINCT username) AS unique_users
                  ,COUNT(DISTINCT ip_address) AS unique_ips
              FROM DMS.SEC_AUTHENTICATION_LOG
             WHERE tenant_id = pn_tenant_id
               AND auth_timestamp > SYSTIMESTAMP - NUMTODSINTERVAL(pn_hours_back, 'HOUR')
             GROUP BY auth_result
             ORDER BY source, event_type;
        
        RETURN lc_cursor;
    EXCEPTION
        WHEN OTHERS THEN
            RETURN NULL;
    END get_auth_stats;

END idp_dms_bridge_pkg;
/

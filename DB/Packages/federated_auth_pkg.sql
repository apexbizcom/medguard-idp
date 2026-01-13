CREATE OR REPLACE PACKAGE IDP.federated_auth_pkg
AUTHID CURRENT_USER
AS
    -- ========================================================================
    -- Package: federated_auth_pkg
    -- Schema:  IDP
    -- Purpose: Multi-protocol federated authentication 
    --          (SAML, LDAP, Custom API, Native, Pass-through)
    -- Version: 1.0
    -- ========================================================================
    
    -- ========================================================================
    -- CONSTANTS
    -- ========================================================================
    
    -- Provider Types
    gc_provider_saml        CONSTANT VARCHAR2(10) := 'SAML';
    gc_provider_ldap        CONSTANT VARCHAR2(10) := 'LDAP';
    gc_provider_oidc        CONSTANT VARCHAR2(10) := 'OIDC';
    gc_provider_custom      CONSTANT VARCHAR2(10) := 'CUSTOM';
    gc_provider_native      CONSTANT VARCHAR2(10) := 'NATIVE';
    
    -- Service Auth Types
    gc_svc_api_key          CONSTANT VARCHAR2(20) := 'API_KEY';
    gc_svc_jwt              CONSTANT VARCHAR2(20) := 'JWT';
    gc_svc_hmac             CONSTANT VARCHAR2(20) := 'HMAC';
    gc_svc_certificate      CONSTANT VARCHAR2(20) := 'CERTIFICATE';
    gc_svc_ip_whitelist     CONSTANT VARCHAR2(20) := 'IP_WHITELIST';
    
    -- Event Types
    gc_event_auth_request   CONSTANT VARCHAR2(20) := 'AUTH_REQUEST';
    gc_event_auth_success   CONSTANT VARCHAR2(20) := 'AUTH_SUCCESS';
    gc_event_auth_failure   CONSTANT VARCHAR2(20) := 'AUTH_FAILURE';
    gc_event_logout         CONSTANT VARCHAR2(20) := 'LOGOUT_REQUEST';
    gc_event_token_issue    CONSTANT VARCHAR2(20) := 'TOKEN_ISSUE';
    gc_event_token_refresh  CONSTANT VARCHAR2(20) := 'TOKEN_REFRESH';
    gc_event_user_provision CONSTANT VARCHAR2(20) := 'USER_PROVISION';
    
    -- ========================================================================
    -- TYPE DEFINITIONS
    -- ========================================================================
    
    TYPE t_auth_result IS RECORD
        (is_authenticated   BOOLEAN
        ,user_id            VARCHAR2(100)
        ,username           VARCHAR2(255)
        ,email              VARCHAR2(255)
        ,first_name         VARCHAR2(100)
        ,last_name          VARCHAR2(100)
        ,display_name       VARCHAR2(255)
        ,roles              VARCHAR2(4000)
        ,session_token      VARCHAR2(256)
        ,expires_at         TIMESTAMP
        ,error_code         VARCHAR2(50)
        ,error_message      VARCHAR2(2000)
        ,provider_type      VARCHAR2(30)
        ,provider_name      VARCHAR2(100)
        ,external_id        VARCHAR2(500)
        ,mfa_required       BOOLEAN
        );
    
    TYPE t_user_attributes IS RECORD
        (username           VARCHAR2(255)
        ,email              VARCHAR2(255)
        ,first_name         VARCHAR2(100)
        ,last_name          VARCHAR2(100)
        ,full_name          VARCHAR2(255)
        ,department         VARCHAR2(100)
        ,job_title          VARCHAR2(100)
        ,phone              VARCHAR2(50)
        ,employee_id        VARCHAR2(100)
        ,groups             VARCHAR2(4000)
        );
    
    -- ========================================================================
    -- MAIN AUTHENTICATION FUNCTIONS
    -- ========================================================================
    
    -- Primary authentication entry point
    FUNCTION authenticate
        (pn_tenant_id       IN  NUMBER
        ,pv_username        IN  VARCHAR2
        ,pv_password        IN  VARCHAR2 DEFAULT NULL
        ,pv_provider_code   IN  VARCHAR2 DEFAULT NULL
        ,pv_saml_response   IN  CLOB DEFAULT NULL
        ,pv_jwt_token       IN  VARCHAR2 DEFAULT NULL
        ,pv_client_ip       IN  VARCHAR2 DEFAULT NULL
        ,pv_user_agent      IN  VARCHAR2 DEFAULT NULL
        )
    RETURN t_auth_result;
    
    -- Authenticate via trusted service (pass-through)
    FUNCTION authenticate_service
        (pn_tenant_id       IN  NUMBER
        ,pv_service_code    IN  VARCHAR2
        ,pv_api_key         IN  VARCHAR2 DEFAULT NULL
        ,pv_api_secret      IN  VARCHAR2 DEFAULT NULL
        ,pv_jwt_token       IN  VARCHAR2 DEFAULT NULL
        ,pv_username        IN  VARCHAR2
        ,pv_client_ip       IN  VARCHAR2 DEFAULT NULL
        )
    RETURN t_auth_result;
    
    -- APEX-compatible authentication function
    FUNCTION apex_authenticate
        (pn_tenant_id       IN  NUMBER
        ,pv_username        IN  VARCHAR2
        ,pv_password        IN  VARCHAR2
        )
    RETURN BOOLEAN;
    
    -- ========================================================================
    -- PROVIDER-SPECIFIC AUTHENTICATION
    -- ========================================================================
    
    FUNCTION authenticate_native
        (pn_tenant_id       IN  NUMBER
        ,pv_username        IN  VARCHAR2
        ,pv_password        IN  VARCHAR2
        ,pv_client_ip       IN  VARCHAR2 DEFAULT NULL
        )
    RETURN t_auth_result;
    
    FUNCTION authenticate_ldap
        (pn_tenant_id       IN  NUMBER
        ,pn_aip_id          IN  NUMBER
        ,pv_username        IN  VARCHAR2
        ,pv_password        IN  VARCHAR2
        ,pv_client_ip       IN  VARCHAR2 DEFAULT NULL
        )
    RETURN t_auth_result;
    
    FUNCTION authenticate_custom
        (pn_tenant_id       IN  NUMBER
        ,pn_aip_id          IN  NUMBER
        ,pv_username        IN  VARCHAR2
        ,pv_password        IN  VARCHAR2
        ,pv_client_ip       IN  VARCHAR2 DEFAULT NULL
        )
    RETURN t_auth_result;
    
    FUNCTION process_saml_response
        (pn_tenant_id       IN  NUMBER
        ,pn_aip_id          IN  NUMBER
        ,pv_saml_response   IN  CLOB
        ,pv_client_ip       IN  VARCHAR2 DEFAULT NULL
        )
    RETURN t_auth_result;
    
    -- ========================================================================
    -- SESSION MANAGEMENT
    -- ========================================================================
    
    FUNCTION create_session
        (pn_tenant_id           IN  NUMBER
        ,pv_user_id             IN  VARCHAR2
        ,pn_aip_id              IN  NUMBER DEFAULT NULL
        ,pn_ats_id              IN  NUMBER DEFAULT NULL
        ,pv_saml_session_index  IN  VARCHAR2 DEFAULT NULL
        ,pv_saml_name_id        IN  VARCHAR2 DEFAULT NULL
        ,pn_duration_seconds    IN  NUMBER DEFAULT 28800
        ,pv_client_ip           IN  VARCHAR2 DEFAULT NULL
        ,pv_user_agent          IN  VARCHAR2 DEFAULT NULL
        )
    RETURN VARCHAR2;
    
    FUNCTION validate_session
        (pn_tenant_id       IN  NUMBER
        ,pv_session_token   IN  VARCHAR2
        )
    RETURN t_auth_result;
    
    PROCEDURE refresh_session
        (pn_tenant_id           IN  NUMBER
        ,pv_session_token       IN  VARCHAR2
        ,pn_extension_seconds   IN  NUMBER DEFAULT 1800
        );
    
    PROCEDURE invalidate_session
        (pn_tenant_id       IN  NUMBER
        ,pv_session_token   IN  VARCHAR2
        ,pv_reason          IN  VARCHAR2 DEFAULT 'USER_LOGOUT'
        );
    
    PROCEDURE invalidate_user_sessions
        (pn_tenant_id       IN  NUMBER
        ,pv_user_id         IN  VARCHAR2
        ,pv_reason          IN  VARCHAR2 DEFAULT 'ADMIN_LOGOUT'
        );
    
    PROCEDURE process_saml_logout
        (pn_tenant_id           IN  NUMBER
        ,pv_saml_session_index  IN  VARCHAR2
        );
    
    PROCEDURE cleanup_expired_sessions
        (pn_tenant_id       IN  NUMBER
        );
    
    -- ========================================================================
    -- USER PROVISIONING (JIT)
    -- ========================================================================
    
    PROCEDURE provision_user
        (pn_tenant_id       IN  NUMBER
        ,pn_aip_id          IN  NUMBER
        ,pv_external_id     IN  VARCHAR2
        ,pt_attributes      IN  t_user_attributes
        ,pb_auto_create     IN  BOOLEAN DEFAULT TRUE
        ,pv_user_id         OUT VARCHAR2
        );
    
    PROCEDURE sync_user_roles
        (pn_tenant_id       IN  NUMBER
        ,pn_aip_id          IN  NUMBER
        ,pv_user_id         IN  VARCHAR2
        ,pv_external_groups IN  VARCHAR2
        );
    
    PROCEDURE link_identity
        (pn_tenant_id           IN  NUMBER
        ,pv_user_id             IN  VARCHAR2
        ,pn_aip_id              IN  NUMBER
        ,pv_external_id         IN  VARCHAR2
        ,pv_external_username   IN  VARCHAR2 DEFAULT NULL
        ,pv_external_email      IN  VARCHAR2 DEFAULT NULL
        );
    
    PROCEDURE unlink_identity
        (pn_tenant_id       IN  NUMBER
        ,pv_user_id         IN  VARCHAR2
        ,pn_aip_id          IN  NUMBER
        );
    
    -- ========================================================================
    -- PROVIDER MANAGEMENT
    -- ========================================================================
    
    FUNCTION get_providers
        (pn_tenant_id       IN  NUMBER
        ,pv_provider_type   IN  VARCHAR2 DEFAULT NULL
        ,pc_providers       OUT SYS_REFCURSOR
        )
    RETURN NUMBER;
    PRAGMA RESTRICT_REFERENCES(get_providers, WNDS);
    
    FUNCTION get_default_provider
        (pn_tenant_id       IN  NUMBER
        )
    RETURN NUMBER;
    PRAGMA RESTRICT_REFERENCES(get_default_provider, WNDS);
    
    FUNCTION test_provider
        (pn_tenant_id       IN  NUMBER
        ,pn_aip_id          IN  NUMBER
        )
    RETURN VARCHAR2;
    
    -- ========================================================================
    -- TRUSTED SERVICE MANAGEMENT
    -- ========================================================================
    
    FUNCTION validate_service
        (pn_tenant_id       IN  NUMBER
        ,pv_service_code    IN  VARCHAR2
        ,pv_api_key         IN  VARCHAR2
        ,pv_api_secret      IN  VARCHAR2 DEFAULT NULL
        ,pv_client_ip       IN  VARCHAR2 DEFAULT NULL
        )
    RETURN NUMBER;
    
    PROCEDURE generate_service_credentials
        (pn_tenant_id       IN  NUMBER
        ,pn_ats_id          IN  NUMBER
        ,pv_api_key         OUT VARCHAR2
        ,pv_api_secret      OUT VARCHAR2
        );
    
    -- ========================================================================
    -- SAML UTILITIES
    -- ========================================================================
    
    FUNCTION generate_saml_request
        (pn_tenant_id       IN  NUMBER
        ,pn_aip_id          IN  NUMBER
        ,pv_relay_state     IN  VARCHAR2 DEFAULT NULL
        )
    RETURN CLOB;
    
    FUNCTION get_saml_sso_url
        (pn_tenant_id       IN  NUMBER
        ,pn_aip_id          IN  NUMBER
        ,pv_relay_state     IN  VARCHAR2 DEFAULT NULL
        )
    RETURN VARCHAR2;
    PRAGMA RESTRICT_REFERENCES(get_saml_sso_url, WNDS);
    
    FUNCTION generate_saml_logout_request
        (pn_tenant_id       IN  NUMBER
        ,pv_session_token   IN  VARCHAR2
        )
    RETURN CLOB;
    
    -- ========================================================================
    -- AUDIT & LOGGING
    -- ========================================================================
    
    PROCEDURE log_auth_event
        (pn_tenant_id       IN  NUMBER
        ,pv_event_type      IN  VARCHAR2
        ,pn_aip_id          IN  NUMBER DEFAULT NULL
        ,pn_ats_id          IN  NUMBER DEFAULT NULL
        ,pv_username        IN  VARCHAR2 DEFAULT NULL
        ,pv_external_id     IN  VARCHAR2 DEFAULT NULL
        ,pb_was_successful  IN  BOOLEAN
        ,pv_error_code      IN  VARCHAR2 DEFAULT NULL
        ,pv_error_message   IN  VARCHAR2 DEFAULT NULL
        ,pv_auth_method     IN  VARCHAR2 DEFAULT NULL
        ,pv_client_ip       IN  VARCHAR2 DEFAULT NULL
        ,pv_user_agent      IN  VARCHAR2 DEFAULT NULL
        ,pv_attributes      IN  CLOB DEFAULT NULL
        );
    
    FUNCTION get_auth_history
        (pn_tenant_id       IN  NUMBER
        ,pv_username        IN  VARCHAR2
        ,pn_days_back       IN  NUMBER DEFAULT 30
        ,pc_history         OUT SYS_REFCURSOR
        )
    RETURN NUMBER;
    
    FUNCTION get_failed_attempts
        (pn_tenant_id       IN  NUMBER
        ,pn_hours_back      IN  NUMBER DEFAULT 24
        ,pn_min_count       IN  NUMBER DEFAULT 3
        ,pc_attempts        OUT SYS_REFCURSOR
        )
    RETURN NUMBER;
    
    -- ========================================================================
    -- HELPER FUNCTIONS
    -- ========================================================================
    
    FUNCTION generate_token
        (pn_length          IN  NUMBER DEFAULT 32
        )
    RETURN VARCHAR2;
    
    FUNCTION hash_secret
        (pv_secret          IN  VARCHAR2
        ,pv_salt            IN  VARCHAR2 DEFAULT NULL
        )
    RETURN VARCHAR2;
    
    FUNCTION verify_secret
        (pv_secret          IN  VARCHAR2
        ,pv_hash            IN  VARCHAR2
        )
    RETURN BOOLEAN;
    
    FUNCTION base64_encode
        (po_data            IN  BLOB
        )
    RETURN CLOB;
    
    FUNCTION base64_decode
        (pv_data            IN  CLOB
        )
    RETURN BLOB;
    
    FUNCTION url_encode
        (pv_data            IN  VARCHAR2
        )
    RETURN VARCHAR2;
    
    FUNCTION url_decode
        (pv_data            IN  VARCHAR2
        )
    RETURN VARCHAR2;

    FUNCTION get_client_ip
    RETURN VARCHAR2;

    FUNCTION apex_authenticate
        (p_username     IN VARCHAR2
        ,p_password     IN VARCHAR2
        )
    RETURN BOOLEAN;

    PROCEDURE apex_post_auth;
    
    PROCEDURE verify_mfa_code
        (p_totp_code        IN  VARCHAR2
        ,p_remember_device  IN  VARCHAR2 DEFAULT 'N'
        ,p_success          OUT VARCHAR2
        ,p_message          OUT VARCHAR2
        );
        
    PROCEDURE verify_backup_code
        (p_backup_code      IN  VARCHAR2
        ,p_success          OUT VARCHAR2
        ,p_message          OUT VARCHAR2
        ,p_codes_remaining  OUT NUMBER
        );
        
    PROCEDURE apex_logout;
    
    PROCEDURE refresh_session;
    
    FUNCTION is_mfa_complete
    RETURN BOOLEAN;
END federated_auth_pkg;
/

CREATE OR REPLACE PACKAGE BODY IDP.federated_auth_pkg
AS
    -- ========================================================================
    -- PRIVATE VARIABLES
    -- ========================================================================
    gv_request_id       VARCHAR2(100);
    
    -- ========================================================================
    -- PRIVATE HELPER: get_client_ip
    -- ========================================================================
    FUNCTION get_client_ip
    RETURN VARCHAR2 IS
        lv_ip   VARCHAR2(50);
    BEGIN
        lv_ip := NVL(V('REMOTE_ADDR')
                    ,NVL(OWA_UTIL.GET_CGI_ENV('REMOTE_ADDR')
                        ,SYS_CONTEXT('USERENV', 'IP_ADDRESS')));
        RETURN lv_ip;
    END get_client_ip;
    
    -- ========================================================================
    -- PRIVATE HELPER: init_request
    -- ========================================================================
    PROCEDURE init_request IS
    BEGIN
        gv_request_id := SYS_GUID();
    END init_request;
    
    -- ========================================================================
    -- generate_token
    -- ========================================================================
    FUNCTION generate_token
        (pn_length          IN  NUMBER DEFAULT 32
        )
    RETURN VARCHAR2 IS
        lo_raw      RAW(64);
    BEGIN
        lo_raw := DBMS_CRYPTO.RANDOMBYTES(pn_length);
        RETURN SUBSTR(RAWTOHEX(lo_raw), 1, pn_length * 2);
    END generate_token;
    
    -- ========================================================================
    -- hash_secret
    -- ========================================================================
    FUNCTION hash_secret
        (pv_secret          IN  VARCHAR2
        ,pv_salt            IN  VARCHAR2 DEFAULT NULL
        )
    RETURN VARCHAR2 IS
        lv_salt     VARCHAR2(64);
        lo_hash     RAW(64);
    BEGIN
        lv_salt := NVL(pv_salt, generate_token(16));
        lo_hash := DBMS_CRYPTO.HASH(
            src => UTL_RAW.CAST_TO_RAW(lv_salt || pv_secret)
           ,typ => DBMS_CRYPTO.HASH_SH512
        );
        RETURN lv_salt || ':' || RAWTOHEX(lo_hash);
    END hash_secret;
    
    -- ========================================================================
    -- verify_secret
    -- ========================================================================
    FUNCTION verify_secret
        (pv_secret          IN  VARCHAR2
        ,pv_hash            IN  VARCHAR2
        )
    RETURN BOOLEAN IS
        lv_salt         VARCHAR2(64);
        ln_pos          NUMBER;
        lv_computed     VARCHAR2(256);
    BEGIN
        ln_pos := INSTR(pv_hash, ':');
        IF ln_pos = 0 THEN
            RETURN FALSE;
        END IF;
        lv_salt := SUBSTR(pv_hash, 1, ln_pos - 1);
        lv_computed := hash_secret(pv_secret, lv_salt);
        RETURN pv_hash = lv_computed;
    END verify_secret;
    
    -- ========================================================================
    -- base64_encode
    -- ========================================================================
    FUNCTION base64_encode
        (po_data            IN  BLOB
        )
    RETURN CLOB IS
    BEGIN
        RETURN UTL_RAW.CAST_TO_VARCHAR2(
            UTL_ENCODE.BASE64_ENCODE(DBMS_LOB.SUBSTR(po_data, 32767, 1))
        );
    END base64_encode;
    
    -- ========================================================================
    -- base64_decode
    -- ========================================================================
    FUNCTION base64_decode
        (pv_data            IN  CLOB
        )
    RETURN BLOB IS
        lo_blob     BLOB;
    BEGIN
        DBMS_LOB.CREATETEMPORARY(lo_blob, TRUE);
        DBMS_LOB.APPEND(lo_blob, UTL_ENCODE.BASE64_DECODE(UTL_RAW.CAST_TO_RAW(pv_data)));
        RETURN lo_blob;
    END base64_decode;
    
    -- ========================================================================
    -- url_encode
    -- ========================================================================
    FUNCTION url_encode
        (pv_data            IN  VARCHAR2
        )
    RETURN VARCHAR2 IS
    BEGIN
        RETURN UTL_URL.ESCAPE(pv_data, TRUE, 'UTF-8');
    END url_encode;
    
    -- ========================================================================
    -- url_decode
    -- ========================================================================
    FUNCTION url_decode
        (pv_data            IN  VARCHAR2
        )
    RETURN VARCHAR2 IS
    BEGIN
        RETURN UTL_URL.UNESCAPE(pv_data, 'UTF-8');
    END url_decode;
    
    -- ========================================================================
    -- log_auth_event
    -- ========================================================================
    PROCEDURE log_auth_event
        (pn_tenant_id       IN  NUMBER
        ,pv_event_type      IN  VARCHAR2
        ,pn_aip_id          IN  NUMBER DEFAULT NULL
        ,pn_ats_id          IN  NUMBER DEFAULT NULL
        ,pv_username        IN  VARCHAR2 DEFAULT NULL
        ,pv_external_id     IN  VARCHAR2 DEFAULT NULL
        ,pb_was_successful  IN  BOOLEAN
        ,pv_error_code      IN  VARCHAR2 DEFAULT NULL
        ,pv_error_message   IN  VARCHAR2 DEFAULT NULL
        ,pv_auth_method     IN  VARCHAR2 DEFAULT NULL
        ,pv_client_ip       IN  VARCHAR2 DEFAULT NULL
        ,pv_user_agent      IN  VARCHAR2 DEFAULT NULL
        ,pv_attributes      IN  CLOB DEFAULT NULL
        ) IS
        lv_provider_type    VARCHAR2(30);
    BEGIN
        -- Get provider type if aip_id provided
        IF pn_aip_id IS NOT NULL THEN
            BEGIN
                SELECT provider_type
                  INTO lv_provider_type
                  FROM IDP.AUTH_IDENTITY_PROVIDERS
                 WHERE aip_id = pn_aip_id;
            EXCEPTION
                WHEN NO_DATA_FOUND THEN
                    lv_provider_type := 'UNKNOWN';
            END;
        ELSE
            lv_provider_type := 'NATIVE';
        END IF;
        
        -- Insert into IDP audit log
        INSERT INTO IDP.AUTH_FEDERATION_LOG
            (tenant_id
            ,event_type
            ,afl_aip_id
            ,afl_ats_id
            ,username
            ,external_id
            ,client_ip
            ,user_agent
            ,was_successful
            ,error_code
            ,error_message
            ,auth_method
            ,attributes_received
            )
        VALUES
            (pn_tenant_id
            ,pv_event_type
            ,pn_aip_id
            ,pn_ats_id
            ,pv_username
            ,pv_external_id
            ,pv_client_ip
            ,pv_user_agent
            ,CASE WHEN pb_was_successful THEN 'Y' ELSE 'N' END
            ,pv_error_code
            ,pv_error_message
            ,pv_auth_method
            ,pv_attributes
            );
        
        -- ================================================================
        -- SOC2 BRIDGE: Log to DMS compliance tables
        -- ================================================================
        BEGIN
            IDP.idp_dms_bridge_pkg.log_to_dms(
                pn_tenant_id        => pn_tenant_id
               ,pv_username         => pv_username
               ,pv_result           => CASE 
                                           WHEN pb_was_successful THEN 'SUCCESS'
                                           WHEN pv_event_type = 'AUTH_FAILURE' THEN 'FAILED'
                                           WHEN pv_event_type = 'LOGOUT_REQUEST' THEN 'LOGOUT'
                                           ELSE pv_event_type
                                       END
               ,pv_ip_address       => pv_client_ip
               ,pv_auth_method      => NVL(pv_auth_method, 
                                           IDP.idp_dms_bridge_pkg.map_provider_to_auth_method(lv_provider_type))
               ,pv_mfa_method       => 'NONE'
               ,pv_failure_reason   => pv_error_message
               ,pv_session_id       => NULL
               ,pv_user_agent       => pv_user_agent
               ,pv_provider_type    => lv_provider_type
            );
        EXCEPTION
            WHEN OTHERS THEN
                -- Don't fail authentication if SOC2 bridge fails
                NULL;
        END;
        
        COMMIT;
        
    EXCEPTION
        WHEN OTHERS THEN
            ROLLBACK;
            RAISE;
    END log_auth_event;

    
    PROCEDURE log_auth_event_old
        (pn_tenant_id       IN  NUMBER
        ,pv_event_type      IN  VARCHAR2
        ,pn_aip_id          IN  NUMBER DEFAULT NULL
        ,pn_ats_id          IN  NUMBER DEFAULT NULL
        ,pv_username        IN  VARCHAR2 DEFAULT NULL
        ,pv_external_id     IN  VARCHAR2 DEFAULT NULL
        ,pb_was_successful  IN  BOOLEAN
        ,pv_error_code      IN  VARCHAR2 DEFAULT NULL
        ,pv_error_message   IN  VARCHAR2 DEFAULT NULL
        ,pv_auth_method     IN  VARCHAR2 DEFAULT NULL
        ,pv_client_ip       IN  VARCHAR2 DEFAULT NULL
        ,pv_user_agent      IN  VARCHAR2 DEFAULT NULL
        ,pv_attributes      IN  CLOB DEFAULT NULL
        )
    IS
        PRAGMA AUTONOMOUS_TRANSACTION;
        lv_was_successful   VARCHAR2(1);
        lv_client_ip        VARCHAR2(4000);
        lv_provider_type    VARCHAR2(4000);
    BEGIN
        lv_client_ip := get_client_ip();
        lv_was_successful := CASE WHEN pb_was_successful THEN 'Y' ELSE 'N' END;
        
        INSERT INTO IDP.AUTH_FEDERATION_LOG
            (tenant_id, event_timestamp, event_type, afl_aip_id, afl_ats_id
            ,username, external_id, client_ip, user_agent, request_id
            ,was_successful, error_code, error_message, auth_method, attributes_received)
        VALUES
            (pn_tenant_id, SYSTIMESTAMP, pv_event_type, pn_aip_id, pn_ats_id
            ,pv_username, pv_external_id, NVL(pv_client_ip, lv_client_ip)
            ,NVL(pv_user_agent, OWA_UTIL.GET_CGI_ENV('HTTP_USER_AGENT'))
            ,gv_request_id, lv_was_successful, pv_error_code, pv_error_message
            ,pv_auth_method, pv_attributes);

        -- Bridge to DMS SOC2 logging
        BEGIN
          SELECT provider_type
            INTO lv_provider_type
            FROM AUTH_IDENTITY_PROVIDERS 
           WHERE aip_id = pn_aip_id;
                                         
            IDP.idp_dms_bridge_pkg.log_to_dms(
                pn_tenant_id        => pn_tenant_id
               ,pv_username         => pv_username
               ,pv_result           => CASE 
                                           WHEN pb_was_successful THEN 'SUCCESS'
                                           WHEN pv_event_type = 'AUTH_FAILURE' THEN 'FAILED'
                                           ELSE pv_event_type
                                       END
               ,pv_ip_address       => pv_client_ip
               ,pv_auth_method      => pv_auth_method
               ,pv_failure_reason   => pv_error_message
               ,pv_user_agent       => pv_user_agent
               ,pv_provider_type    => lv_provider_type
            );
        EXCEPTION
            WHEN OTHERS THEN
                NULL; -- Don't fail authentication if bridge fails
        END;
    
            COMMIT;
        EXCEPTION
            WHEN OTHERS THEN
                ROLLBACK;
        END log_auth_event_old;
    
    -- ========================================================================
    -- get_default_provider
    -- ========================================================================
    FUNCTION get_default_provider
        (pn_tenant_id       IN  NUMBER
        )
    RETURN NUMBER IS
        ln_aip_id   NUMBER;
    BEGIN
        SELECT aip.aip_id
          INTO ln_aip_id
          FROM IDP.AUTH_IDENTITY_PROVIDERS aip
         WHERE aip.tenant_id = pn_tenant_id
           AND aip.is_active = 'Y'
           AND aip.is_default = 'Y'
           AND ROWNUM = 1;
        RETURN ln_aip_id;
    EXCEPTION
        WHEN NO_DATA_FOUND THEN
            BEGIN
                SELECT aip.aip_id
                  INTO ln_aip_id
                  FROM IDP.AUTH_IDENTITY_PROVIDERS aip
                 WHERE aip.tenant_id = pn_tenant_id
                   AND aip.is_active = 'Y'
                 ORDER BY aip.priority_order
                 FETCH FIRST 1 ROW ONLY;
                RETURN ln_aip_id;
            EXCEPTION
                WHEN NO_DATA_FOUND THEN
                    RETURN NULL;
            END;
    END get_default_provider;
    
    -- ========================================================================
    -- create_session
    -- ========================================================================
    FUNCTION create_session
        (pn_tenant_id           IN  NUMBER
        ,pv_user_id             IN  VARCHAR2
        ,pn_aip_id              IN  NUMBER DEFAULT NULL
        ,pn_ats_id              IN  NUMBER DEFAULT NULL
        ,pv_saml_session_index  IN  VARCHAR2 DEFAULT NULL
        ,pv_saml_name_id        IN  VARCHAR2 DEFAULT NULL
        ,pn_duration_seconds    IN  NUMBER DEFAULT 28800
        ,pv_client_ip           IN  VARCHAR2 DEFAULT NULL
        ,pv_user_agent          IN  VARCHAR2 DEFAULT NULL
        )
    RETURN VARCHAR2 IS
        lv_token            VARCHAR2(256);
        lv_refresh          VARCHAR2(256);
        lv_client_ip        VARCHAR2(4000);
        lv_session_token    VARCHAR2(4000);
    BEGIN
        lv_client_ip := get_client_ip();
        lv_token := generate_token(64);
        lv_refresh := generate_token(64);
        
        INSERT INTO IDP.AUTH_SSO_SESSIONS
            (tenant_id, user_id, aso_aip_id, aso_ats_id, session_token, refresh_token
            ,saml_session_index, saml_name_id, expires_date, client_ip, user_agent)
        VALUES
            (pn_tenant_id, pv_user_id, pn_aip_id, pn_ats_id, lv_token, lv_refresh
            ,pv_saml_session_index, pv_saml_name_id
            ,SYSTIMESTAMP + NUMTODSINTERVAL(pn_duration_seconds, 'SECOND')
            ,NVL(pv_client_ip, lv_client_ip)
            ,NVL(pv_user_agent, OWA_UTIL.GET_CGI_ENV('HTTP_USER_AGENT')));

        -- Bridge to DMS session management
        BEGIN
            IDP.idp_dms_bridge_pkg.bridge_create_session(
                pn_tenant_id        => pn_tenant_id
               ,pv_user_id          => pv_user_id
               ,pv_session_token    => lv_session_token
               ,pv_ip_address       => pv_client_ip
               ,pn_timeout_minutes  => ROUND(pn_duration_seconds / 60)
            );
        EXCEPTION
            WHEN OTHERS THEN
                NULL;
        END;
        
        log_auth_event(
            pn_tenant_id        => pn_tenant_id
           ,pv_event_type       => gc_event_token_issue
           ,pn_aip_id           => pn_aip_id
           ,pn_ats_id           => pn_ats_id
           ,pv_username         => pv_user_id
           ,pb_was_successful   => TRUE
           ,pv_client_ip        => pv_client_ip
        );
        
        COMMIT;
        RETURN lv_token;
    END create_session;
    
    -- ========================================================================
    -- validate_session
    -- ========================================================================
    FUNCTION validate_session
        (pn_tenant_id       IN  NUMBER
        ,pv_session_token   IN  VARCHAR2
        )
    RETURN t_auth_result IS
        lt_result       t_auth_result;
        ln_aso_id       NUMBER;
        lv_user_id      VARCHAR2(100);
        ld_expires      TIMESTAMP;
        ln_aip_id       NUMBER;
        ln_ats_id       NUMBER;
    BEGIN
        SELECT aso.aso_id, aso.user_id, aso.expires_date, aso.aso_aip_id, aso.aso_ats_id
          INTO ln_aso_id, lv_user_id, ld_expires, ln_aip_id, ln_ats_id
          FROM IDP.AUTH_SSO_SESSIONS aso
         WHERE aso.tenant_id = pn_tenant_id
           AND aso.session_token = pv_session_token
           AND aso.is_valid = 'Y'
           AND aso.expires_date > SYSTIMESTAMP;
        
        UPDATE IDP.AUTH_SSO_SESSIONS
           SET last_activity = SYSTIMESTAMP
         WHERE aso_id = ln_aso_id;
        
        lt_result.is_authenticated := TRUE;
        lt_result.user_id := lv_user_id;
        lt_result.session_token := pv_session_token;
        lt_result.expires_at := ld_expires;
        
        IF ln_aip_id IS NOT NULL THEN
            SELECT aip.provider_type, aip.provider_name
              INTO lt_result.provider_type, lt_result.provider_name
              FROM IDP.AUTH_IDENTITY_PROVIDERS aip
             WHERE aip.aip_id = ln_aip_id;
        ELSIF ln_ats_id IS NOT NULL THEN
            SELECT 'SERVICE', ats.service_name
              INTO lt_result.provider_type, lt_result.provider_name
              FROM IDP.AUTH_TRUSTED_SERVICES ats
             WHERE ats.ats_id = ln_ats_id;
        END IF;
        
        COMMIT;
        RETURN lt_result;
    EXCEPTION
        WHEN NO_DATA_FOUND THEN
            lt_result.is_authenticated := FALSE;
            lt_result.error_code := 'INVALID_SESSION';
            lt_result.error_message := 'Session not found or expired';
            RETURN lt_result;
    END validate_session;
    
    -- ========================================================================
    -- refresh_session
    -- ========================================================================
    PROCEDURE refresh_session
        (pn_tenant_id           IN  NUMBER
        ,pv_session_token       IN  VARCHAR2
        ,pn_extension_seconds   IN  NUMBER DEFAULT 1800
        )
    IS
    BEGIN
        UPDATE IDP.AUTH_SSO_SESSIONS
           SET last_activity = SYSTIMESTAMP
              ,expires_date = SYSTIMESTAMP + NUMTODSINTERVAL(pn_extension_seconds, 'SECOND')
         WHERE tenant_id = pn_tenant_id
           AND session_token = pv_session_token
           AND is_valid = 'Y';
        COMMIT;
    END refresh_session;
    
    -- ========================================================================
    -- invalidate_session
    -- ========================================================================
    PROCEDURE invalidate_session
        (pn_tenant_id       IN  NUMBER
        ,pv_session_token   IN  VARCHAR2
        ,pv_reason          IN  VARCHAR2 DEFAULT 'USER_LOGOUT'
        )
    IS
    BEGIN
        UPDATE IDP.AUTH_SSO_SESSIONS
           SET is_valid = 'N'
              ,invalidation_reason = pv_reason
              ,invalidated_date = SYSTIMESTAMP
         WHERE tenant_id = pn_tenant_id
           AND session_token = pv_session_token;

    -- Bridge to DMS session termination
    BEGIN
        IDP.idp_dms_bridge_pkg.bridge_terminate_session(
            pn_tenant_id        => pn_tenant_id
           ,pv_session_token    => pv_session_token
           ,pv_reason           => pv_reason
        );
    EXCEPTION
        WHEN OTHERS THEN
            NULL;
    END;

        COMMIT;
    END invalidate_session;
    
    -- ========================================================================
    -- invalidate_user_sessions
    -- ========================================================================
    PROCEDURE invalidate_user_sessions
        (pn_tenant_id       IN  NUMBER
        ,pv_user_id         IN  VARCHAR2
        ,pv_reason          IN  VARCHAR2 DEFAULT 'ADMIN_LOGOUT'
        )
    IS
    BEGIN
        UPDATE IDP.AUTH_SSO_SESSIONS
           SET is_valid = 'N'
              ,invalidation_reason = pv_reason
              ,invalidated_date = SYSTIMESTAMP
         WHERE tenant_id = pn_tenant_id
           AND user_id = pv_user_id
           AND is_valid = 'Y';
        COMMIT;
    END invalidate_user_sessions;
    
    -- ========================================================================
    -- process_saml_logout
    -- ========================================================================
    PROCEDURE process_saml_logout
        (pn_tenant_id           IN  NUMBER
        ,pv_saml_session_index  IN  VARCHAR2
        )
    IS
    BEGIN
        UPDATE IDP.AUTH_SSO_SESSIONS
           SET is_valid = 'N'
              ,invalidation_reason = 'SAML_SLO'
              ,invalidated_date = SYSTIMESTAMP
         WHERE tenant_id = pn_tenant_id
           AND saml_session_index = pv_saml_session_index
           AND is_valid = 'Y';
        COMMIT;
    END process_saml_logout;
    
    -- ========================================================================
    -- cleanup_expired_sessions
    -- ========================================================================
    PROCEDURE cleanup_expired_sessions
        (pn_tenant_id       IN  NUMBER
        )
    IS
    BEGIN
        UPDATE IDP.AUTH_SSO_SESSIONS
           SET is_valid = 'N'
              ,invalidation_reason = 'EXPIRED'
              ,invalidated_date = SYSTIMESTAMP
         WHERE tenant_id = pn_tenant_id
           AND is_valid = 'Y'
           AND expires_date < SYSTIMESTAMP;
        
        DELETE FROM IDP.AUTH_SSO_SESSIONS
         WHERE tenant_id = pn_tenant_id
           AND is_valid = 'N'
           AND invalidated_date < SYSTIMESTAMP - INTERVAL '90' DAY;
        
        COMMIT;
    END cleanup_expired_sessions;
    
    -- ========================================================================
    -- authenticate_native
    -- ========================================================================
    FUNCTION authenticate_native
        (pn_tenant_id       IN  NUMBER
        ,pv_username        IN  VARCHAR2
        ,pv_password        IN  VARCHAR2
        ,pv_client_ip       IN  VARCHAR2 DEFAULT NULL
        )
    RETURN t_auth_result IS
        lt_result       t_auth_result;
    BEGIN
        init_request();
        lt_result.provider_type := gc_provider_native;
        lt_result.provider_name := 'Native Database';
        
        log_auth_event(
            pn_tenant_id        => pn_tenant_id
           ,pv_event_type       => gc_event_auth_request
           ,pv_username         => pv_username
           ,pb_was_successful   => TRUE
           ,pv_auth_method      => 'NATIVE'
           ,pv_client_ip        => pv_client_ip
        );
        
        -- NOTE: This is a stub. In production, integrate with your user table
        -- Example: Query DMS.DOC_USERS or your application's user table
        
        lt_result.is_authenticated := TRUE;
        lt_result.user_id := pv_username;
        lt_result.username := pv_username;
        lt_result.email := pv_username || '@example.com';
        lt_result.first_name := 'User';
        lt_result.last_name := pv_username;
        lt_result.display_name := 'User ' || pv_username;
        lt_result.mfa_required := FALSE;
        
        lt_result.session_token := create_session(
            pn_tenant_id    => pn_tenant_id
           ,pv_user_id      => pv_username
           ,pv_client_ip    => pv_client_ip
        );
        lt_result.expires_at := SYSTIMESTAMP + INTERVAL '8' HOUR;
        
        log_auth_event(
            pn_tenant_id        => pn_tenant_id
           ,pv_event_type       => gc_event_auth_success
           ,pv_username         => pv_username
           ,pb_was_successful   => TRUE
           ,pv_auth_method      => 'NATIVE'
           ,pv_client_ip        => pv_client_ip
        );
        
        RETURN lt_result;
    END authenticate_native;
    
    -- ========================================================================
    -- authenticate_ldap (stub)
    -- ========================================================================
    FUNCTION authenticate_ldap
        (pn_tenant_id       IN  NUMBER
        ,pn_aip_id          IN  NUMBER
        ,pv_username        IN  VARCHAR2
        ,pv_password        IN  VARCHAR2
        ,pv_client_ip       IN  VARCHAR2 DEFAULT NULL
        )
    RETURN t_auth_result IS
        lt_result   t_auth_result;
    BEGIN
        init_request();
        lt_result.is_authenticated := FALSE;
        lt_result.error_code := 'LDAP_NOT_CONFIGURED';
        lt_result.error_message := 'LDAP authentication requires DBMS_LDAP setup';
        lt_result.provider_type := gc_provider_ldap;
        RETURN lt_result;
    END authenticate_ldap;
    
    -- ========================================================================
    -- authenticate_custom (stub)
    -- ========================================================================
    FUNCTION authenticate_custom
        (pn_tenant_id       IN  NUMBER
        ,pn_aip_id          IN  NUMBER
        ,pv_username        IN  VARCHAR2
        ,pv_password        IN  VARCHAR2
        ,pv_client_ip       IN  VARCHAR2 DEFAULT NULL
        )
    RETURN t_auth_result IS
        lt_result   t_auth_result;
    BEGIN
        init_request();
        lt_result.is_authenticated := FALSE;
        lt_result.error_code := 'CUSTOM_NOT_CONFIGURED';
        lt_result.error_message := 'Custom API authentication requires configuration';
        lt_result.provider_type := gc_provider_custom;
        RETURN lt_result;
    END authenticate_custom;
    
    -- ========================================================================
    -- process_saml_response (stub)
    -- ========================================================================
    FUNCTION process_saml_response
        (pn_tenant_id       IN  NUMBER
        ,pn_aip_id          IN  NUMBER
        ,pv_saml_response   IN  CLOB
        ,pv_client_ip       IN  VARCHAR2 DEFAULT NULL
        )
    RETURN t_auth_result IS
        lt_result   t_auth_result;
    BEGIN
        init_request();
        lt_result.is_authenticated := FALSE;
        lt_result.error_code := 'SAML_NOT_CONFIGURED';
        lt_result.error_message := 'SAML requires XML parsing library configuration';
        lt_result.provider_type := gc_provider_saml;
        RETURN lt_result;
    END process_saml_response;
    
    -- ========================================================================
    -- authenticate (main entry point)
    -- ========================================================================
    FUNCTION authenticate
        (pn_tenant_id       IN  NUMBER
        ,pv_username        IN  VARCHAR2
        ,pv_password        IN  VARCHAR2 DEFAULT NULL
        ,pv_provider_code   IN  VARCHAR2 DEFAULT NULL
        ,pv_saml_response   IN  CLOB DEFAULT NULL
        ,pv_jwt_token       IN  VARCHAR2 DEFAULT NULL
        ,pv_client_ip       IN  VARCHAR2 DEFAULT NULL
        ,pv_user_agent      IN  VARCHAR2 DEFAULT NULL
        )
    RETURN t_auth_result IS
        lt_result           t_auth_result;
        ln_aip_id           NUMBER;
        lv_provider_type    VARCHAR2(30);
    BEGIN
        init_request();
        
        IF pv_provider_code IS NOT NULL THEN
            BEGIN
                SELECT aip.aip_id, aip.provider_type
                  INTO ln_aip_id, lv_provider_type
                  FROM IDP.AUTH_IDENTITY_PROVIDERS aip
                 WHERE aip.tenant_id = pn_tenant_id
                   AND aip.provider_code = pv_provider_code
                   AND aip.is_active = 'Y';
            EXCEPTION
                WHEN NO_DATA_FOUND THEN
                    lt_result.is_authenticated := FALSE;
                    lt_result.error_code := 'INVALID_PROVIDER';
                    lt_result.error_message := 'Provider not found';
                    RETURN lt_result;
            END;
        ELSE
            ln_aip_id := get_default_provider(pn_tenant_id);
            IF ln_aip_id IS NOT NULL THEN
                SELECT aip.provider_type
                  INTO lv_provider_type
                  FROM IDP.AUTH_IDENTITY_PROVIDERS aip
                 WHERE aip.aip_id = ln_aip_id;
            ELSE
                lv_provider_type := gc_provider_native;
            END IF;
        END IF;
       
        -- Bridge authentication result to DMS SOC2
        BEGIN
            IDP.idp_dms_bridge_pkg.log_to_dms(
                pn_tenant_id        => pn_tenant_id
               ,pv_username         => lt_result.username
               ,pv_result           => CASE 
                                           WHEN lt_result.is_authenticated THEN 'SUCCESS'
                                           ELSE 'FAILED'
                                       END
               ,pv_ip_address       => pv_client_ip
               ,pv_auth_method      => lt_result.provider_type
               ,pv_mfa_method       => CASE WHEN lt_result.mfa_required THEN 'REQUIRED' ELSE 'NONE' END
               ,pv_failure_reason   => lt_result.error_message
               ,pv_session_id       => lt_result.session_token
               ,pv_user_agent       => pv_user_agent
               ,pv_provider_type    => lt_result.provider_type
            );
        EXCEPTION
            WHEN OTHERS THEN
                NULL;
        END;       
        
        IF lv_provider_type = gc_provider_native OR ln_aip_id IS NULL THEN
            RETURN authenticate_native(pn_tenant_id, pv_username, pv_password, pv_client_ip);
        ELSIF lv_provider_type = gc_provider_ldap THEN
            RETURN authenticate_ldap(pn_tenant_id, ln_aip_id, pv_username, pv_password, pv_client_ip);
        ELSIF lv_provider_type = gc_provider_saml THEN
            IF pv_saml_response IS NOT NULL THEN
                RETURN process_saml_response(pn_tenant_id, ln_aip_id, pv_saml_response, pv_client_ip);
            ELSE
                lt_result.is_authenticated := FALSE;
                lt_result.error_code := 'SAML_REDIRECT';
                lt_result.error_message := get_saml_sso_url(pn_tenant_id, ln_aip_id);
                RETURN lt_result;
            END IF;
        ELSIF lv_provider_type = gc_provider_custom THEN
            RETURN authenticate_custom(pn_tenant_id, ln_aip_id, pv_username, pv_password, pv_client_ip);
        ELSE
            lt_result.is_authenticated := FALSE;
            lt_result.error_code := 'UNSUPPORTED_PROVIDER';
            lt_result.error_message := 'Provider type not supported';
            RETURN lt_result;
        END IF;
    END authenticate;
    
    -- ========================================================================
    -- authenticate_service (pass-through)
    -- ========================================================================
    FUNCTION authenticate_service
        (pn_tenant_id       IN  NUMBER
        ,pv_service_code    IN  VARCHAR2
        ,pv_api_key         IN  VARCHAR2 DEFAULT NULL
        ,pv_api_secret      IN  VARCHAR2 DEFAULT NULL
        ,pv_jwt_token       IN  VARCHAR2 DEFAULT NULL
        ,pv_username        IN  VARCHAR2
        ,pv_client_ip       IN  VARCHAR2 DEFAULT NULL
        )
    RETURN t_auth_result IS
        lt_result       t_auth_result;
        ln_ats_id       NUMBER;
        lv_service_name VARCHAR2(100);
        ln_max_duration NUMBER;
    BEGIN
        init_request();
        ln_ats_id := validate_service(pn_tenant_id, pv_service_code, pv_api_key, pv_api_secret, pv_client_ip);
        
        IF ln_ats_id IS NULL THEN
            lt_result.is_authenticated := FALSE;
            lt_result.error_code := 'INVALID_SERVICE';
            lt_result.error_message := 'Service authentication failed';
            log_auth_event(pn_tenant_id, gc_event_auth_failure, NULL, NULL, pv_username,
                          NULL, FALSE, 'INVALID_SERVICE', NULL, 'SERVICE_PASSTHROUGH', pv_client_ip);
            RETURN lt_result;
        END IF;
        
        SELECT ats.service_name, ats.max_session_duration
          INTO lv_service_name, ln_max_duration
          FROM IDP.AUTH_TRUSTED_SERVICES ats
         WHERE ats.ats_id = ln_ats_id;
        
        UPDATE IDP.AUTH_TRUSTED_SERVICES
           SET last_used_date = SYSTIMESTAMP
              ,last_used_ip = pv_client_ip
         WHERE ats_id = ln_ats_id;
        
        lt_result.is_authenticated := TRUE;
        lt_result.user_id := pv_username;
        lt_result.username := pv_username;
        lt_result.provider_type := 'SERVICE';
        lt_result.provider_name := lv_service_name;
        
        lt_result.session_token := create_session(
            pn_tenant_id            => pn_tenant_id
           ,pv_user_id              => pv_username
           ,pn_ats_id               => ln_ats_id
           ,pn_duration_seconds     => ln_max_duration
           ,pv_client_ip            => pv_client_ip
        );
        lt_result.expires_at := SYSTIMESTAMP + NUMTODSINTERVAL(ln_max_duration, 'SECOND');
        
        log_auth_event(pn_tenant_id, gc_event_auth_success, NULL, ln_ats_id, pv_username,
                      NULL, TRUE, NULL, NULL, 'SERVICE_PASSTHROUGH', pv_client_ip);
        
        COMMIT;
        RETURN lt_result;
    END authenticate_service;
    
    -- ========================================================================
    -- apex_authenticate
    -- ========================================================================
    FUNCTION apex_authenticate
        (pn_tenant_id       IN  NUMBER
        ,pv_username        IN  VARCHAR2
        ,pv_password        IN  VARCHAR2
        )
    RETURN BOOLEAN IS
        lt_result   t_auth_result;
    BEGIN
        lt_result := authenticate(pn_tenant_id, pv_username, pv_password, NULL, NULL, NULL, V('REMOTE_ADDR'));
        
        IF lt_result.is_authenticated THEN
            APEX_UTIL.SET_SESSION_STATE('G_USER_ID', lt_result.user_id);
            APEX_UTIL.SET_SESSION_STATE('G_USER_EMAIL', lt_result.email);
            APEX_UTIL.SET_SESSION_STATE('G_USER_DISPLAY_NAME', lt_result.display_name);
            APEX_UTIL.SET_SESSION_STATE('G_AUTH_PROVIDER', lt_result.provider_name);
            APEX_UTIL.SET_SESSION_STATE('G_SESSION_TOKEN', lt_result.session_token);
        END IF;
        
        RETURN lt_result.is_authenticated;
    END apex_authenticate;
    
    -- ========================================================================
    -- provision_user (stub)
    -- ========================================================================
    PROCEDURE provision_user
        (pn_tenant_id       IN  NUMBER
        ,pn_aip_id          IN  NUMBER
        ,pv_external_id     IN  VARCHAR2
        ,pt_attributes      IN  t_user_attributes
        ,pb_auto_create     IN  BOOLEAN DEFAULT TRUE
        ,pv_user_id         OUT VARCHAR2
        )
    IS
    BEGIN
        pv_user_id := pt_attributes.username;
    END provision_user;
    
    -- ========================================================================
    -- sync_user_roles (stub)
    -- ========================================================================
    PROCEDURE sync_user_roles
        (pn_tenant_id       IN  NUMBER
        ,pn_aip_id          IN  NUMBER
        ,pv_user_id         IN  VARCHAR2
        ,pv_external_groups IN  VARCHAR2
        )
    IS
    BEGIN
        NULL;
    END sync_user_roles;
    
    -- ========================================================================
    -- link_identity
    -- ========================================================================
    PROCEDURE link_identity
        (pn_tenant_id           IN  NUMBER
        ,pv_user_id             IN  VARCHAR2
        ,pn_aip_id              IN  NUMBER
        ,pv_external_id         IN  VARCHAR2
        ,pv_external_username   IN  VARCHAR2 DEFAULT NULL
        ,pv_external_email      IN  VARCHAR2 DEFAULT NULL
        )
    IS
    BEGIN
        MERGE INTO IDP.AUTH_FEDERATED_IDENTITIES t
        USING (SELECT pn_tenant_id tn, pv_user_id ui, pn_aip_id ai, pv_external_id ei FROM DUAL) s
        ON (t.tenant_id = s.tn AND t.afi_aip_id = s.ai AND t.external_id = s.ei)
        WHEN MATCHED THEN
            UPDATE SET user_id = s.ui, last_auth_date = SYSTIMESTAMP
        WHEN NOT MATCHED THEN
            INSERT (tenant_id, user_id, afi_aip_id, external_id, external_username, external_email, linked_by)
            VALUES (s.tn, s.ui, s.ai, s.ei, pv_external_username, pv_external_email, USER);
        COMMIT;
    END link_identity;
    
    -- ========================================================================
    -- unlink_identity
    -- ========================================================================
    PROCEDURE unlink_identity
        (pn_tenant_id       IN  NUMBER
        ,pv_user_id         IN  VARCHAR2
        ,pn_aip_id          IN  NUMBER
        )
    IS
    BEGIN
        UPDATE IDP.AUTH_FEDERATED_IDENTITIES
           SET is_active = 'N'
              ,modified_date = SYSTIMESTAMP
         WHERE tenant_id = pn_tenant_id
           AND user_id = pv_user_id
           AND afi_aip_id = pn_aip_id;
        COMMIT;
    END unlink_identity;
    
    -- ========================================================================
    -- get_providers
    -- ========================================================================
    FUNCTION get_providers
        (pn_tenant_id       IN  NUMBER
        ,pv_provider_type   IN  VARCHAR2 DEFAULT NULL
        ,pc_providers       OUT SYS_REFCURSOR
        )
    RETURN NUMBER IS
        ln_count    NUMBER := 0;
    BEGIN
        SELECT COUNT(*)
          INTO ln_count
          FROM IDP.AUTH_IDENTITY_PROVIDERS aip
         WHERE aip.tenant_id = pn_tenant_id
           AND aip.is_active = 'Y'
           AND (pv_provider_type IS NULL OR aip.provider_type = pv_provider_type);
        
        OPEN pc_providers FOR
            SELECT aip.aip_id, aip.provider_name, aip.provider_code, aip.provider_type
                  ,aip.display_name, aip.is_default, aip.priority_order
              FROM IDP.AUTH_IDENTITY_PROVIDERS aip
             WHERE aip.tenant_id = pn_tenant_id
               AND aip.is_active = 'Y'
               AND (pv_provider_type IS NULL OR aip.provider_type = pv_provider_type)
             ORDER BY aip.priority_order;
        
        RETURN ln_count;
    END get_providers;
    
    -- ========================================================================
    -- test_provider
    -- ========================================================================
    FUNCTION test_provider
        (pn_tenant_id       IN  NUMBER
        ,pn_aip_id          IN  NUMBER
        )
    RETURN VARCHAR2 IS
        ln_count    NUMBER;
    BEGIN
        SELECT COUNT(*)
          INTO ln_count
          FROM IDP.AUTH_IDENTITY_PROVIDERS aip
         WHERE aip.aip_id = pn_aip_id
           AND aip.tenant_id = pn_tenant_id;
        
        IF ln_count > 0 THEN
            RETURN '{"success":true,"message":"Provider configuration found"}';
        ELSE
            RETURN '{"success":false,"message":"Provider not found"}';
        END IF;
    END test_provider;
    
    -- ========================================================================
    -- validate_service
    -- ========================================================================
    FUNCTION validate_service
        (pn_tenant_id       IN  NUMBER
        ,pv_service_code    IN  VARCHAR2
        ,pv_api_key         IN  VARCHAR2
        ,pv_api_secret      IN  VARCHAR2 DEFAULT NULL
        ,pv_client_ip       IN  VARCHAR2 DEFAULT NULL
        )
    RETURN NUMBER IS
        ln_ats_id           NUMBER;
        lv_stored_key       VARCHAR2(256);
        lv_stored_hash      VARCHAR2(256);
        lv_auth_type        VARCHAR2(30);
        lv_allowed_ips      VARCHAR2(2000);
    BEGIN
        SELECT ats.ats_id, ats.api_key, ats.api_secret_hash, ats.auth_type, ats.allowed_ips
          INTO ln_ats_id, lv_stored_key, lv_stored_hash, lv_auth_type, lv_allowed_ips
          FROM IDP.AUTH_TRUSTED_SERVICES ats
         WHERE ats.tenant_id = pn_tenant_id
           AND ats.service_code = pv_service_code
           AND ats.is_active = 'Y';
        
        IF lv_auth_type = gc_svc_api_key THEN
            IF lv_stored_key = pv_api_key THEN
                IF lv_stored_hash IS NULL OR verify_secret(pv_api_secret, lv_stored_hash) THEN
                    RETURN ln_ats_id;
                END IF;
            END IF;
        ELSIF lv_auth_type = gc_svc_ip_whitelist AND lv_allowed_ips IS NOT NULL THEN
            IF INSTR(',' || lv_allowed_ips || ',', ',' || pv_client_ip || ',') > 0 THEN
                RETURN ln_ats_id;
            END IF;
        END IF;
        
        RETURN NULL;
    EXCEPTION
        WHEN NO_DATA_FOUND THEN
            RETURN NULL;
    END validate_service;
    
    -- ========================================================================
    -- generate_service_credentials
    -- ========================================================================
    PROCEDURE generate_service_credentials
        (pn_tenant_id       IN  NUMBER
        ,pn_ats_id          IN  NUMBER
        ,pv_api_key         OUT VARCHAR2
        ,pv_api_secret      OUT VARCHAR2
        )
    IS
    BEGIN
        pv_api_key := 'CV-' || generate_token(16);
        pv_api_secret := generate_token(32);
        
        UPDATE IDP.AUTH_TRUSTED_SERVICES
           SET api_key = pv_api_key
              ,api_secret_hash = hash_secret(pv_api_secret)
              ,modified_date = SYSTIMESTAMP
         WHERE ats_id = pn_ats_id
           AND tenant_id = pn_tenant_id;
        COMMIT;
    END generate_service_credentials;
    
    -- ========================================================================
    -- SAML utilities (stubs)
    -- ========================================================================
    FUNCTION generate_saml_request
        (pn_tenant_id       IN  NUMBER
        ,pn_aip_id          IN  NUMBER
        ,pv_relay_state     IN  VARCHAR2 DEFAULT NULL
        )
    RETURN CLOB IS
    BEGIN
        RETURN NULL;
    END generate_saml_request;
    
    FUNCTION get_saml_sso_url
        (pn_tenant_id       IN  NUMBER
        ,pn_aip_id          IN  NUMBER
        ,pv_relay_state     IN  VARCHAR2 DEFAULT NULL
        )
    RETURN VARCHAR2 IS
        lv_sso_url  VARCHAR2(1000);
    BEGIN
        SELECT asg.sso_url
          INTO lv_sso_url
          FROM IDP.AUTH_SAML_CONFIG asg
         WHERE asg.asg_aip_id = pn_aip_id;
        RETURN lv_sso_url;
    EXCEPTION
        WHEN NO_DATA_FOUND THEN
            RETURN NULL;
    END get_saml_sso_url;
    
    FUNCTION generate_saml_logout_request
        (pn_tenant_id       IN  NUMBER
        ,pv_session_token   IN  VARCHAR2
        )
    RETURN CLOB IS
    BEGIN
        RETURN NULL;
    END generate_saml_logout_request;
    
    -- ========================================================================
    -- Audit functions
    -- ========================================================================
    FUNCTION get_auth_history
        (pn_tenant_id       IN  NUMBER
        ,pv_username        IN  VARCHAR2
        ,pn_days_back       IN  NUMBER DEFAULT 30
        ,pc_history         OUT SYS_REFCURSOR
        )
    RETURN NUMBER IS
        ln_count    NUMBER := 0;
    BEGIN
        SELECT COUNT(*)
          INTO ln_count
          FROM IDP.AUTH_FEDERATION_LOG afl
         WHERE afl.tenant_id = pn_tenant_id
           AND afl.username = pv_username
           AND afl.event_timestamp > SYSTIMESTAMP - NUMTODSINTERVAL(pn_days_back, 'DAY');
        
        OPEN pc_history FOR
            SELECT afl.afl_id, afl.event_timestamp, afl.event_type, afl.was_successful
                  ,afl.error_code, afl.error_message, afl.auth_method, afl.client_ip
              FROM IDP.AUTH_FEDERATION_LOG afl
             WHERE afl.tenant_id = pn_tenant_id
               AND afl.username = pv_username
               AND afl.event_timestamp > SYSTIMESTAMP - NUMTODSINTERVAL(pn_days_back, 'DAY')
             ORDER BY afl.event_timestamp DESC;
        
        RETURN ln_count;
    END get_auth_history;
    
    FUNCTION get_failed_attempts
        (pn_tenant_id       IN  NUMBER
        ,pn_hours_back      IN  NUMBER DEFAULT 24
        ,pn_min_count       IN  NUMBER DEFAULT 3
        ,pc_attempts        OUT SYS_REFCURSOR
        )
    RETURN NUMBER IS
        ln_count    NUMBER := 0;
    BEGIN
        OPEN pc_attempts FOR
            SELECT afl.username, afl.client_ip, COUNT(*) AS attempt_count
                  ,MIN(afl.event_timestamp) AS first_attempt
                  ,MAX(afl.event_timestamp) AS last_attempt
              FROM IDP.AUTH_FEDERATION_LOG afl
             WHERE afl.tenant_id = pn_tenant_id
               AND afl.was_successful = 'N'
               AND afl.event_type = 'AUTH_FAILURE'
               AND afl.event_timestamp > SYSTIMESTAMP - NUMTODSINTERVAL(pn_hours_back, 'HOUR')
             GROUP BY afl.username, afl.client_ip
            HAVING COUNT(*) >= pn_min_count
             ORDER BY COUNT(*) DESC;
        
        RETURN ln_count;
    END get_failed_attempts;

    -- ============================================================================
    -- SECTION 1: Main APEX Authentication Function
    -- ============================================================================
    FUNCTION apex_authenticate
        (p_username     IN VARCHAR2
        ,p_password     IN VARCHAR2
        )
    RETURN BOOLEAN
    AS
        lt_result           T_AUTH_RESULT;
        lt_mfa_status       MFA_AUTH_PKG.T_MFA_STATUS;
        ln_tenant_id        NUMBER;
        lv_client_ip        VARCHAR2(50);
        lv_user_agent       VARCHAR2(1000);
        lv_device_token     VARCHAR2(256);
        lb_device_trusted   BOOLEAN := FALSE;
    BEGIN
        -- ========================================================================
        -- Get tenant ID from APEX application item or default
        -- ========================================================================
        BEGIN
            ln_tenant_id := NVL(TO_NUMBER(V('G_TENANT_ID')), 1);
        EXCEPTION
            WHEN OTHERS THEN
                ln_tenant_id := 1;
        END;
        
        -- ========================================================================
        -- Get client information
        -- ========================================================================
        BEGIN
            lv_client_ip := OWA_UTIL.GET_CGI_ENV('REMOTE_ADDR');
            lv_user_agent := SUBSTR(OWA_UTIL.GET_CGI_ENV('HTTP_USER_AGENT'), 1, 1000);
        EXCEPTION
            WHEN OTHERS THEN
                lv_client_ip := 'UNKNOWN';
                lv_user_agent := 'UNKNOWN';
        END;
        
        -- ========================================================================
        -- Call federated authentication
        -- This automatically logs to both IDP and DMS SOC2 via bridge
        -- ========================================================================
        lt_result := IDP.federated_auth_pkg.authenticate(
            pn_tenant_id    => ln_tenant_id
           ,pv_username     => p_username
           ,pv_password     => p_password
           ,pv_client_ip    => lv_client_ip
           ,pv_user_agent   => lv_user_agent
        );
        
        -- ========================================================================
        -- Handle authentication failure
        -- ========================================================================
        IF NOT lt_result.is_authenticated THEN
            -- Already logged via bridge - just return false
            RETURN FALSE;
        END IF;
        
        -- ========================================================================
        -- Check if MFA is required
        -- ========================================================================
        lt_mfa_status := IDP.mfa_auth_pkg.get_mfa_status(
            pn_tenant_id    => ln_tenant_id
           ,pv_user_id      => lt_result.user_id
        );
        
        -- ========================================================================
        -- Check for trusted device (skip MFA if trusted)
        -- ========================================================================
        IF lt_mfa_status.is_required OR lt_result.mfa_required THEN
            -- Check device trust cookie
            BEGIN
                lv_device_token := OWA_COOKIE.GET('MFA_DEVICE_TOKEN').vals(1);
                IF lv_device_token IS NOT NULL THEN
                    lb_device_trusted := IDP.mfa_auth_pkg.is_device_trusted(
                        pn_tenant_id    => ln_tenant_id
                       ,pv_user_id      => lt_result.user_id
                       ,pv_device_token => lv_device_token
                    );
                END IF;
            EXCEPTION
                WHEN OTHERS THEN
                    lb_device_trusted := FALSE;
            END;
        END IF;
        
        -- ========================================================================
        -- Store session information in APEX
        -- ========================================================================
        -- Store IDP session token
        APEX_UTIL.SET_SESSION_STATE('G_IDP_SESSION_TOKEN', lt_result.session_token);
        
        -- Store user information
        APEX_UTIL.SET_SESSION_STATE('G_USER_EMAIL', lt_result.email);
        APEX_UTIL.SET_SESSION_STATE('G_USER_DISPLAY_NAME', lt_result.display_name);
        APEX_UTIL.SET_SESSION_STATE('G_USER_ROLES', lt_result.roles);
        APEX_UTIL.SET_SESSION_STATE('G_AUTH_PROVIDER', lt_result.provider_type);
        
        -- ========================================================================
        -- Handle MFA requirement
        -- ========================================================================
        IF (lt_mfa_status.is_required OR lt_result.mfa_required) 
           AND NOT lb_device_trusted 
           AND lt_mfa_status.is_enrolled THEN
            -- MFA required and user is enrolled - need verification
            APEX_UTIL.SET_SESSION_STATE('G_PENDING_USER', lt_result.user_id);
            APEX_UTIL.SET_SESSION_STATE('G_MFA_REQUIRED', 'Y');
            APEX_UTIL.SET_SESSION_STATE('G_MFA_VERIFIED', 'N');
        ELSIF (lt_mfa_status.is_required OR lt_result.mfa_required) 
              AND NOT lb_device_trusted 
              AND NOT lt_mfa_status.is_enrolled
              AND lt_mfa_status.in_grace_period THEN
            -- MFA required but user not enrolled and in grace period
            APEX_UTIL.SET_SESSION_STATE('G_MFA_REQUIRED', 'Y');
            APEX_UTIL.SET_SESSION_STATE('G_MFA_VERIFIED', 'N');
            APEX_UTIL.SET_SESSION_STATE('G_MFA_ENROLL_REQUIRED', 'Y');
            APEX_UTIL.SET_SESSION_STATE('G_MFA_GRACE_DAYS', TO_CHAR(lt_mfa_status.grace_days_left));
        ELSIF (lt_mfa_status.is_required OR lt_result.mfa_required) 
              AND NOT lb_device_trusted 
              AND NOT lt_mfa_status.is_enrolled
              AND NOT lt_mfa_status.in_grace_period THEN
            -- MFA required, not enrolled, grace period expired - must enroll
            APEX_UTIL.SET_SESSION_STATE('G_MFA_REQUIRED', 'Y');
            APEX_UTIL.SET_SESSION_STATE('G_MFA_VERIFIED', 'N');
            APEX_UTIL.SET_SESSION_STATE('G_MFA_ENROLL_REQUIRED', 'Y');
            APEX_UTIL.SET_SESSION_STATE('G_MFA_GRACE_DAYS', '0');
        ELSE
            -- MFA not required or device is trusted
            APEX_UTIL.SET_SESSION_STATE('G_MFA_REQUIRED', 'N');
            APEX_UTIL.SET_SESSION_STATE('G_MFA_VERIFIED', 'Y');
        END IF;
        
        -- Authentication successful
        RETURN TRUE;
        
    EXCEPTION
        WHEN OTHERS THEN
            -- Log error internally but don't expose to user
            RETURN FALSE;
    END apex_authenticate;

    -- ============================================================================
    -- SECTION 2: APEX Post-Authentication Procedure
    -- ============================================================================
    -- Call this from APEX Application Process (After Authentication)
    PROCEDURE apex_post_auth
    AS
        lv_mfa_required     VARCHAR2(1);
        lv_mfa_verified     VARCHAR2(1);
        lv_enroll_required  VARCHAR2(1);
    BEGIN
        -- Get MFA status from session
        lv_mfa_required := V('G_MFA_REQUIRED');
        lv_mfa_verified := V('G_MFA_VERIFIED');
        lv_enroll_required := V('G_MFA_ENROLL_REQUIRED');
        
        -- Redirect based on MFA status
        IF lv_mfa_required = 'Y' AND NVL(lv_mfa_verified, 'N') = 'N' THEN
            IF lv_enroll_required = 'Y' THEN
                -- Redirect to MFA enrollment page
                APEX_UTIL.REDIRECT_URL(
                    p_url => APEX_PAGE.GET_URL(p_page => 105)  -- MFA Enrollment
                );
            ELSE
                -- Redirect to MFA verification page
                APEX_UTIL.REDIRECT_URL(
                    p_url => APEX_PAGE.GET_URL(p_page => 102)  -- MFA Verify
                );
            END IF;
        END IF;
        
        -- If we get here, no redirect needed
    END apex_post_auth;
    
    -- ============================================================================
    -- SECTION 3: MFA Verification Procedure (for Page 102)
    -- ============================================================================
    PROCEDURE verify_mfa_code
        (p_totp_code        IN  VARCHAR2
        ,p_remember_device  IN  VARCHAR2 DEFAULT 'N'
        ,p_success          OUT VARCHAR2
        ,p_message          OUT VARCHAR2
        )
    AS
        lb_valid            BOOLEAN;
        ln_tenant_id        NUMBER;
        lv_user_id          VARCHAR2(100);
        lv_client_ip        VARCHAR2(50);
        lv_user_agent       VARCHAR2(1000);
        lv_device_token     VARCHAR2(256);
    BEGIN
        -- Initialize
        p_success := 'N';
        p_message := NULL;
        
        -- Get session values
        ln_tenant_id := NVL(TO_NUMBER(V('G_TENANT_ID')), 1);
        lv_user_id := V('G_PENDING_USER');
        
        IF lv_user_id IS NULL THEN
            lv_user_id := V('APP_USER');
        END IF;
        
        IF lv_user_id IS NULL THEN
            p_message := 'Session expired. Please log in again.';
            RETURN;
        END IF;
        
        -- Get client info
        lv_client_ip := OWA_UTIL.GET_CGI_ENV('REMOTE_ADDR');
        lv_user_agent := SUBSTR(OWA_UTIL.GET_CGI_ENV('HTTP_USER_AGENT'), 1, 1000);
        
        -- Verify TOTP code
        -- This automatically logs to DMS SOC2 via bridge!
        lb_valid := IDP.mfa_auth_pkg.verify_totp(
            pn_tenant_id    => ln_tenant_id
           ,pv_user_id      => lv_user_id
           ,pv_totp_code    => p_totp_code
           ,pv_client_ip    => lv_client_ip
           ,pv_session_id   => V('APP_SESSION')
        );
        
        IF NOT lb_valid THEN
            p_message := 'Invalid code. Please try again.';
            RETURN;
        END IF;
        
        -- MFA verified!
        APEX_UTIL.SET_SESSION_STATE('G_MFA_VERIFIED', 'Y');
        APEX_UTIL.SET_SESSION_STATE('G_PENDING_USER', NULL);
        
        -- Handle "Remember this device"
        IF UPPER(p_remember_device) = 'Y' THEN
            lb_valid := IDP.mfa_auth_pkg.trust_device(
                pn_tenant_id    => ln_tenant_id
               ,pv_user_id      => lv_user_id
               ,pv_device_name  => 'Web Browser'
               ,pv_user_agent   => lv_user_agent
               ,pv_client_ip    => lv_client_ip
               ,pv_device_token => lv_device_token
            );
            
            -- Set cookie for trusted device
            IF lv_device_token IS NOT NULL THEN
                OWA_COOKIE.SEND(
                    name    => 'MFA_DEVICE_TOKEN'
                   ,value   => lv_device_token
                   ,expires => SYSDATE + 30
                   ,domain  => NULL
                   ,path    => '/'
                   ,secure  => 'Y'
                   ,httponly => 'Y'
                );
            END IF;
        END IF;
        
        p_success := 'Y';
        p_message := 'Verification successful.';
        
    EXCEPTION
        WHEN OTHERS THEN
            p_success := 'N';
            p_message := 'An error occurred. Please try again.';
    END verify_mfa_code;
    
    -- ============================================================================
    -- SECTION 4: Backup Code Verification Procedure
    -- ============================================================================
    PROCEDURE verify_backup_code
        (p_backup_code      IN  VARCHAR2
        ,p_success          OUT VARCHAR2
        ,p_message          OUT VARCHAR2
        ,p_codes_remaining  OUT NUMBER
        )
    AS
        lb_valid            BOOLEAN;
        ln_tenant_id        NUMBER;
        lv_user_id          VARCHAR2(100);
        lv_client_ip        VARCHAR2(50);
    BEGIN
        -- Initialize
        p_success := 'N';
        p_message := NULL;
        p_codes_remaining := 0;
        
        -- Get session values
        ln_tenant_id := NVL(TO_NUMBER(V('G_TENANT_ID')), 1);
        lv_user_id := NVL(V('G_PENDING_USER'), V('APP_USER'));
        lv_client_ip := OWA_UTIL.GET_CGI_ENV('REMOTE_ADDR');
        
        IF lv_user_id IS NULL THEN
            p_message := 'Session expired. Please log in again.';
            RETURN;
        END IF;
        
        -- Verify backup code
        -- This automatically logs to DMS SOC2 via bridge!
        lb_valid := IDP.mfa_auth_pkg.verify_backup_code(
            pn_tenant_id    => ln_tenant_id
           ,pv_user_id      => lv_user_id
           ,pv_backup_code  => p_backup_code
           ,pv_client_ip    => lv_client_ip
        );
        
        IF NOT lb_valid THEN
            p_message := 'Invalid backup code.';
            RETURN;
        END IF;
        
        -- Get remaining codes count
        p_codes_remaining := IDP.mfa_auth_pkg.get_backup_code_count(
            pn_tenant_id    => ln_tenant_id
           ,pv_user_id      => lv_user_id
        );
        
        -- MFA verified!
        APEX_UTIL.SET_SESSION_STATE('G_MFA_VERIFIED', 'Y');
        APEX_UTIL.SET_SESSION_STATE('G_PENDING_USER', NULL);
        
        p_success := 'Y';
        IF p_codes_remaining <= 2 THEN
            p_message := 'Verification successful. Warning: Only ' || 
                         p_codes_remaining || ' backup code(s) remaining!';
        ELSE
            p_message := 'Verification successful.';
        END IF;
        
    EXCEPTION
        WHEN OTHERS THEN
            p_success := 'N';
            p_message := 'An error occurred. Please try again.';
    END verify_backup_code;

    -- ============================================================================
    -- SECTION 5: Logout Procedure
    -- ============================================================================
    PROCEDURE apex_logout
    AS
        ln_tenant_id        NUMBER;
        lv_session_token    VARCHAR2(256);
    BEGIN
        -- Get session values
        ln_tenant_id := NVL(TO_NUMBER(V('G_TENANT_ID')), 1);
        lv_session_token := V('G_IDP_SESSION_TOKEN');
        
        -- Invalidate IDP session (logs to SOC2 automatically)
        IF lv_session_token IS NOT NULL THEN
            IDP.federated_auth_pkg.invalidate_session(
                pn_tenant_id    => ln_tenant_id
               ,pv_session_token => lv_session_token
               ,pv_reason       => 'USER_LOGOUT'
            );
        END IF;
        
        -- Clear session state
        APEX_UTIL.SET_SESSION_STATE('G_IDP_SESSION_TOKEN', NULL);
        APEX_UTIL.SET_SESSION_STATE('G_MFA_REQUIRED', NULL);
        APEX_UTIL.SET_SESSION_STATE('G_MFA_VERIFIED', NULL);
        APEX_UTIL.SET_SESSION_STATE('G_PENDING_USER', NULL);
        
    EXCEPTION
        WHEN OTHERS THEN
            NULL; -- Don't fail logout
    END apex_logout;

    -- ============================================================================
    -- SECTION 6: Session Refresh Procedure
    -- ============================================================================
    PROCEDURE refresh_session
    AS
        ln_tenant_id        NUMBER;
        lv_session_token    VARCHAR2(256);
    BEGIN
        ln_tenant_id := NVL(TO_NUMBER(V('G_TENANT_ID')), 1);
        lv_session_token := V('G_IDP_SESSION_TOKEN');
        
        IF lv_session_token IS NOT NULL THEN
            IDP.federated_auth_pkg.refresh_session(
                pn_tenant_id        => ln_tenant_id
               ,pv_session_token    => lv_session_token
               ,pn_extension_seconds => 1800  -- 30 minutes
            );
        END IF;
        
    EXCEPTION
        WHEN OTHERS THEN
            NULL; -- Don't fail on refresh
    END refresh_session;

    -- ============================================================================
    -- SECTION 7: Page Security Check Function
    -- ============================================================================
    -- Use this in Authorization Schemes to ensure MFA is complete
    FUNCTION is_mfa_complete
    RETURN BOOLEAN
    AS
        lv_mfa_required VARCHAR2(1);
        lv_mfa_verified VARCHAR2(1);
    BEGIN
        lv_mfa_required := V('G_MFA_REQUIRED');
        lv_mfa_verified := V('G_MFA_VERIFIED');
        
        -- If MFA not required, access granted
        IF NVL(lv_mfa_required, 'N') = 'N' THEN
            RETURN TRUE;
        END IF;
        
        -- If MFA required, check if verified
        RETURN (NVL(lv_mfa_verified, 'N') = 'Y');
    END is_mfa_complete;
END federated_auth_pkg;
/

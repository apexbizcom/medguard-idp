-- ============================================================================
-- Identity Provider (IDP) Schema - Federated Authentication Tables
-- ============================================================================
-- Schema: IDP
-- Purpose: Standalone Identity Provider module for multi-protocol authentication
-- Version: 1.0
-- ============================================================================
--
-- TABLE ALIASES:
--   AUTH_IDENTITY_PROVIDERS  - aip
--   AUTH_SAML_CONFIG         - asg
--   AUTH_SAML_ATTRIBUTE_MAP  - asm
--   AUTH_LDAP_CONFIG         - alg
--   AUTH_CUSTOM_CONFIG       - acg
--   AUTH_GROUP_ROLE_MAP      - agp
--   AUTH_TRUSTED_SERVICES    - ats
--   AUTH_FEDERATED_IDENTITIES- afi
--   AUTH_SSO_SESSIONS        - aso
--   AUTH_FEDERATION_LOG      - afl
--
-- ============================================================================

SET DEFINE OFF;
SET SERVEROUTPUT ON SIZE UNLIMITED;

PROMPT ========================================================================
PROMPT IDP Schema - Federated Authentication Tables Installation
PROMPT ========================================================================

-- ============================================================================
-- SECTION 1: AUTH_IDENTITY_PROVIDERS (Alias: aip)
-- Core identity provider configuration
-- ============================================================================

CREATE TABLE IDP.AUTH_IDENTITY_PROVIDERS
    (aip_id                     NUMBER GENERATED ALWAYS AS IDENTITY
    ,tenant_id                  NUMBER NOT NULL
    ,provider_name              VARCHAR2(100) NOT NULL
    ,provider_code              VARCHAR2(50) NOT NULL
    ,provider_type              VARCHAR2(30) NOT NULL
    ,display_name               VARCHAR2(255)
    ,description                VARCHAR2(1000)
    ,is_active                  VARCHAR2(1) DEFAULT 'Y'
    ,is_default                 VARCHAR2(1) DEFAULT 'N'
    ,priority_order             NUMBER DEFAULT 1
    ,endpoint_url               VARCHAR2(1000)
    ,metadata_url               VARCHAR2(1000)
    ,connection_timeout         NUMBER DEFAULT 30
    ,request_timeout            NUMBER DEFAULT 60
    ,max_retries                NUMBER DEFAULT 3
    ,created_date               TIMESTAMP DEFAULT SYSTIMESTAMP
    ,created_by                 VARCHAR2(100) DEFAULT USER
    ,modified_date              TIMESTAMP
    ,modified_by                VARCHAR2(100)
    ,CONSTRAINT aip_pk PRIMARY KEY (aip_id)
    ,CONSTRAINT aip_provider_type_chk 
        CHECK (provider_type IN ('SAML','LDAP','OIDC','CUSTOM','NATIVE'))
    ,CONSTRAINT aip_is_active_chk 
        CHECK (is_active IN ('Y','N'))
    ,CONSTRAINT aip_is_default_chk 
        CHECK (is_default IN ('Y','N'))
    ,CONSTRAINT aip_tenant_code_uk 
        UNIQUE (tenant_id, provider_code)
    );

CREATE INDEX IDP.aip_tenant_idx 
    ON IDP.AUTH_IDENTITY_PROVIDERS(tenant_id, is_active);

CREATE INDEX IDP.aip_provider_type_idx 
    ON IDP.AUTH_IDENTITY_PROVIDERS(provider_type, is_active);

COMMENT ON TABLE IDP.AUTH_IDENTITY_PROVIDERS 
    IS 'Configuration for identity providers (SAML IdPs, LDAP servers, custom systems)';

PROMPT Created: AUTH_IDENTITY_PROVIDERS (aip)

-- ============================================================================
-- SECTION 2: AUTH_SAML_CONFIG (Alias: asg)
-- SAML 2.0 specific configuration
-- ============================================================================

CREATE TABLE IDP.AUTH_SAML_CONFIG
    (asg_id                     NUMBER GENERATED ALWAYS AS IDENTITY
    ,asg_aip_id                 NUMBER NOT NULL
    ,idp_entity_id              VARCHAR2(500) NOT NULL
    ,sp_entity_id               VARCHAR2(500) NOT NULL
    ,sso_url                    VARCHAR2(1000) NOT NULL
    ,slo_url                    VARCHAR2(1000)
    ,artifact_resolution_url    VARCHAR2(1000)
    ,idp_certificate            CLOB
    ,sp_certificate             CLOB
    ,sp_private_key             CLOB
    ,sso_binding                VARCHAR2(50) DEFAULT 'HTTP-POST'
    ,slo_binding                VARCHAR2(50) DEFAULT 'HTTP-POST'
    ,sign_authn_requests        VARCHAR2(1) DEFAULT 'Y'
    ,sign_logout_requests       VARCHAR2(1) DEFAULT 'Y'
    ,want_assertions_signed     VARCHAR2(1) DEFAULT 'Y'
    ,want_assertions_encrypted  VARCHAR2(1) DEFAULT 'N'
    ,signature_algorithm        VARCHAR2(100) DEFAULT 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'
    ,digest_algorithm           VARCHAR2(100) DEFAULT 'http://www.w3.org/2001/04/xmlenc#sha256'
    ,max_auth_lifetime          NUMBER DEFAULT 28800
    ,force_reauth               VARCHAR2(1) DEFAULT 'N'
    ,created_date               TIMESTAMP DEFAULT SYSTIMESTAMP
    ,created_by                 VARCHAR2(100) DEFAULT USER
    ,modified_date              TIMESTAMP
    ,modified_by                VARCHAR2(100)
    ,CONSTRAINT asg_pk PRIMARY KEY (asg_id)
    ,CONSTRAINT asg_aip_id_fk 
        FOREIGN KEY (asg_aip_id) 
        REFERENCES IDP.AUTH_IDENTITY_PROVIDERS(aip_id)
    ,CONSTRAINT asg_sso_binding_chk 
        CHECK (sso_binding IN ('HTTP-POST','HTTP-REDIRECT','HTTP-ARTIFACT'))
    ,CONSTRAINT asg_slo_binding_chk 
        CHECK (slo_binding IN ('HTTP-POST','HTTP-REDIRECT'))
    ,CONSTRAINT asg_sign_authn_chk 
        CHECK (sign_authn_requests IN ('Y','N'))
    ,CONSTRAINT asg_sign_logout_chk 
        CHECK (sign_logout_requests IN ('Y','N'))
    ,CONSTRAINT asg_want_signed_chk 
        CHECK (want_assertions_signed IN ('Y','N'))
    ,CONSTRAINT asg_want_encrypted_chk 
        CHECK (want_assertions_encrypted IN ('Y','N'))
    ,CONSTRAINT asg_force_reauth_chk 
        CHECK (force_reauth IN ('Y','N'))
    );

CREATE INDEX IDP.asg_aip_id_idx 
    ON IDP.AUTH_SAML_CONFIG(asg_aip_id);

COMMENT ON TABLE IDP.AUTH_SAML_CONFIG 
    IS 'SAML 2.0 specific configuration for identity providers';

PROMPT Created: AUTH_SAML_CONFIG (asg)

-- ============================================================================
-- SECTION 3: AUTH_SAML_ATTRIBUTE_MAP (Alias: asm)
-- SAML assertion attribute mappings
-- ============================================================================

CREATE TABLE IDP.AUTH_SAML_ATTRIBUTE_MAP
    (asm_id                     NUMBER GENERATED ALWAYS AS IDENTITY
    ,asm_asg_id                 NUMBER NOT NULL
    ,saml_attribute             VARCHAR2(255) NOT NULL
    ,target_attribute           VARCHAR2(100) NOT NULL
    ,is_required                VARCHAR2(1) DEFAULT 'N'
    ,default_value              VARCHAR2(500)
    ,transformation             VARCHAR2(100)
    ,created_date               TIMESTAMP DEFAULT SYSTIMESTAMP
    ,created_by                 VARCHAR2(100) DEFAULT USER
    ,CONSTRAINT asm_pk PRIMARY KEY (asm_id)
    ,CONSTRAINT asm_asg_id_fk 
        FOREIGN KEY (asm_asg_id) 
        REFERENCES IDP.AUTH_SAML_CONFIG(asg_id)
    ,CONSTRAINT asm_target_attr_chk 
        CHECK (target_attribute IN ('USERNAME','EMAIL','FIRST_NAME','LAST_NAME',
                                    'FULL_NAME','EMPLOYEE_ID','DEPARTMENT',
                                    'JOB_TITLE','PHONE','ROLES','GROUPS'))
    ,CONSTRAINT asm_is_required_chk 
        CHECK (is_required IN ('Y','N'))
    ,CONSTRAINT asm_transformation_chk 
        CHECK (transformation IN ('NONE','LOWERCASE','UPPERCASE','TRIM',
                                  'EXTRACT_DOMAIN','SPLIT_FIRST','SPLIT_LAST'))
    ,CONSTRAINT asm_saml_attr_uk 
        UNIQUE (asm_asg_id, saml_attribute)
    );

CREATE INDEX IDP.asm_asg_id_idx 
    ON IDP.AUTH_SAML_ATTRIBUTE_MAP(asm_asg_id);

COMMENT ON TABLE IDP.AUTH_SAML_ATTRIBUTE_MAP 
    IS 'Maps SAML assertion attributes to application user attributes';

PROMPT Created: AUTH_SAML_ATTRIBUTE_MAP (asm)

-- ============================================================================
-- SECTION 4: AUTH_LDAP_CONFIG (Alias: alg)
-- LDAP/Active Directory configuration
-- ============================================================================

CREATE TABLE IDP.AUTH_LDAP_CONFIG
    (alg_id                     NUMBER GENERATED ALWAYS AS IDENTITY
    ,alg_aip_id                 NUMBER NOT NULL
    ,server_host                VARCHAR2(255) NOT NULL
    ,server_port                NUMBER DEFAULT 389
    ,use_ssl                    VARCHAR2(1) DEFAULT 'N'
    ,use_tls                    VARCHAR2(1) DEFAULT 'Y'
    ,ssl_certificate            CLOB
    ,bind_dn                    VARCHAR2(500)
    ,bind_password              VARCHAR2(500)
    ,base_dn                    VARCHAR2(500) NOT NULL
    ,user_search_base           VARCHAR2(500)
    ,user_search_filter         VARCHAR2(500) DEFAULT '(&(objectClass=user)(sAMAccountName={username}))'
    ,group_search_base          VARCHAR2(500)
    ,group_search_filter        VARCHAR2(500) DEFAULT '(&(objectClass=group)(member={userdn}))'
    ,username_attribute         VARCHAR2(100) DEFAULT 'sAMAccountName'
    ,email_attribute            VARCHAR2(100) DEFAULT 'mail'
    ,firstname_attribute        VARCHAR2(100) DEFAULT 'givenName'
    ,lastname_attribute         VARCHAR2(100) DEFAULT 'sn'
    ,displayname_attribute      VARCHAR2(100) DEFAULT 'displayName'
    ,memberof_attribute         VARCHAR2(100) DEFAULT 'memberOf'
    ,auth_method                VARCHAR2(30) DEFAULT 'SIMPLE'
    ,referral_handling          VARCHAR2(20) DEFAULT 'FOLLOW'
    ,pool_size                  NUMBER DEFAULT 10
    ,pool_timeout               NUMBER DEFAULT 300
    ,created_date               TIMESTAMP DEFAULT SYSTIMESTAMP
    ,created_by                 VARCHAR2(100) DEFAULT USER
    ,modified_date              TIMESTAMP
    ,modified_by                VARCHAR2(100)
    ,CONSTRAINT alg_pk PRIMARY KEY (alg_id)
    ,CONSTRAINT alg_aip_id_fk 
        FOREIGN KEY (alg_aip_id) 
        REFERENCES IDP.AUTH_IDENTITY_PROVIDERS(aip_id)
    ,CONSTRAINT alg_use_ssl_chk 
        CHECK (use_ssl IN ('Y','N'))
    ,CONSTRAINT alg_use_tls_chk 
        CHECK (use_tls IN ('Y','N'))
    ,CONSTRAINT alg_auth_method_chk 
        CHECK (auth_method IN ('SIMPLE','DIGEST-MD5','GSSAPI'))
    ,CONSTRAINT alg_referral_chk 
        CHECK (referral_handling IN ('FOLLOW','IGNORE','THROW'))
    );

CREATE INDEX IDP.alg_aip_id_idx 
    ON IDP.AUTH_LDAP_CONFIG(alg_aip_id);

COMMENT ON TABLE IDP.AUTH_LDAP_CONFIG 
    IS 'LDAP/Active Directory configuration for authentication';

PROMPT Created: AUTH_LDAP_CONFIG (alg)

-- ============================================================================
-- SECTION 5: AUTH_CUSTOM_CONFIG (Alias: acg)
-- Custom REST API authentication configuration
-- ============================================================================

CREATE TABLE IDP.AUTH_CUSTOM_CONFIG
    (acg_id                     NUMBER GENERATED ALWAYS AS IDENTITY
    ,acg_aip_id                 NUMBER NOT NULL
    ,auth_endpoint              VARCHAR2(1000) NOT NULL
    ,auth_method                VARCHAR2(10) DEFAULT 'POST'
    ,content_type               VARCHAR2(100) DEFAULT 'application/json'
    ,request_template           CLOB
    ,success_field              VARCHAR2(100) DEFAULT 'success'
    ,success_value              VARCHAR2(100) DEFAULT 'true'
    ,error_field                VARCHAR2(100) DEFAULT 'error'
    ,user_data_field            VARCHAR2(100) DEFAULT 'user'
    ,api_key_header             VARCHAR2(100)
    ,api_key_value              VARCHAR2(500)
    ,custom_headers             CLOB
    ,verify_ssl                 VARCHAR2(1) DEFAULT 'Y'
    ,client_certificate         CLOB
    ,client_private_key         CLOB
    ,username_path              VARCHAR2(255) DEFAULT '$.user.username'
    ,email_path                 VARCHAR2(255) DEFAULT '$.user.email'
    ,roles_path                 VARCHAR2(255) DEFAULT '$.user.roles'
    ,created_date               TIMESTAMP DEFAULT SYSTIMESTAMP
    ,created_by                 VARCHAR2(100) DEFAULT USER
    ,modified_date              TIMESTAMP
    ,modified_by                VARCHAR2(100)
    ,CONSTRAINT acg_pk PRIMARY KEY (acg_id)
    ,CONSTRAINT acg_aip_id_fk 
        FOREIGN KEY (acg_aip_id) 
        REFERENCES IDP.AUTH_IDENTITY_PROVIDERS(aip_id)
    ,CONSTRAINT acg_auth_method_chk 
        CHECK (auth_method IN ('GET','POST'))
    ,CONSTRAINT acg_verify_ssl_chk 
        CHECK (verify_ssl IN ('Y','N'))
    );

CREATE INDEX IDP.acg_aip_id_idx 
    ON IDP.AUTH_CUSTOM_CONFIG(acg_aip_id);

COMMENT ON TABLE IDP.AUTH_CUSTOM_CONFIG 
    IS 'Configuration for custom REST API authentication endpoints';

PROMPT Created: AUTH_CUSTOM_CONFIG (acg)

-- ============================================================================
-- SECTION 6: AUTH_GROUP_ROLE_MAP (Alias: agp)
-- External group to application role mappings
-- ============================================================================

CREATE TABLE IDP.AUTH_GROUP_ROLE_MAP
    (agp_id                     NUMBER GENERATED ALWAYS AS IDENTITY
    ,agp_aip_id                 NUMBER NOT NULL
    ,external_group             VARCHAR2(500) NOT NULL
    ,target_role_id             NUMBER NOT NULL
    ,target_role_name           VARCHAR2(100)
    ,auto_provision             VARCHAR2(1) DEFAULT 'Y'
    ,is_active                  VARCHAR2(1) DEFAULT 'Y'
    ,created_date               TIMESTAMP DEFAULT SYSTIMESTAMP
    ,created_by                 VARCHAR2(100) DEFAULT USER
    ,CONSTRAINT agp_pk PRIMARY KEY (agp_id)
    ,CONSTRAINT agp_aip_id_fk 
        FOREIGN KEY (agp_aip_id) 
        REFERENCES IDP.AUTH_IDENTITY_PROVIDERS(aip_id)
    ,CONSTRAINT agp_auto_provision_chk 
        CHECK (auto_provision IN ('Y','N'))
    ,CONSTRAINT agp_is_active_chk 
        CHECK (is_active IN ('Y','N'))
    ,CONSTRAINT agp_ext_group_uk 
        UNIQUE (agp_aip_id, external_group)
    );

CREATE INDEX IDP.agp_aip_id_idx 
    ON IDP.AUTH_GROUP_ROLE_MAP(agp_aip_id);

COMMENT ON TABLE IDP.AUTH_GROUP_ROLE_MAP 
    IS 'Maps external IdP groups to application roles for auto-provisioning';

PROMPT Created: AUTH_GROUP_ROLE_MAP (agp)

-- ============================================================================
-- SECTION 7: AUTH_TRUSTED_SERVICES (Alias: ats)
-- Trusted external services for pass-through authentication
-- ============================================================================

CREATE TABLE IDP.AUTH_TRUSTED_SERVICES
    (ats_id                     NUMBER GENERATED ALWAYS AS IDENTITY
    ,tenant_id                  NUMBER NOT NULL
    ,service_name               VARCHAR2(100) NOT NULL
    ,service_code               VARCHAR2(50) NOT NULL
    ,description                VARCHAR2(1000)
    ,auth_type                  VARCHAR2(30) NOT NULL
    ,api_key                    VARCHAR2(256)
    ,api_secret_hash            VARCHAR2(256)
    ,jwt_issuer                 VARCHAR2(255)
    ,jwt_audience               VARCHAR2(255)
    ,jwt_secret                 VARCHAR2(500)
    ,jwt_algorithm              VARCHAR2(20) DEFAULT 'RS256'
    ,allowed_ips                VARCHAR2(2000)
    ,client_certificate         CLOB
    ,certificate_fingerprint    VARCHAR2(128)
    ,can_authenticate           VARCHAR2(1) DEFAULT 'Y'
    ,can_read_documents         VARCHAR2(1) DEFAULT 'N'
    ,can_write_documents        VARCHAR2(1) DEFAULT 'N'
    ,can_admin                  VARCHAR2(1) DEFAULT 'N'
    ,max_session_duration       NUMBER DEFAULT 3600
    ,token_expiry_seconds       NUMBER DEFAULT 3600
    ,is_active                  VARCHAR2(1) DEFAULT 'Y'
    ,created_date               TIMESTAMP DEFAULT SYSTIMESTAMP
    ,created_by                 VARCHAR2(100) DEFAULT USER
    ,modified_date              TIMESTAMP
    ,modified_by                VARCHAR2(100)
    ,last_used_date             TIMESTAMP
    ,last_used_ip               VARCHAR2(50)
    ,CONSTRAINT ats_pk PRIMARY KEY (ats_id)
    ,CONSTRAINT ats_auth_type_chk 
        CHECK (auth_type IN ('API_KEY','JWT','HMAC','CERTIFICATE','IP_WHITELIST'))
    ,CONSTRAINT ats_jwt_algorithm_chk 
        CHECK (jwt_algorithm IN ('HS256','HS384','HS512','RS256','RS384','RS512'))
    ,CONSTRAINT ats_can_auth_chk 
        CHECK (can_authenticate IN ('Y','N'))
    ,CONSTRAINT ats_can_read_chk 
        CHECK (can_read_documents IN ('Y','N'))
    ,CONSTRAINT ats_can_write_chk 
        CHECK (can_write_documents IN ('Y','N'))
    ,CONSTRAINT ats_can_admin_chk 
        CHECK (can_admin IN ('Y','N'))
    ,CONSTRAINT ats_is_active_chk 
        CHECK (is_active IN ('Y','N'))
    ,CONSTRAINT ats_tenant_code_uk 
        UNIQUE (tenant_id, service_code)
    );

CREATE INDEX IDP.ats_tenant_idx 
    ON IDP.AUTH_TRUSTED_SERVICES(tenant_id, is_active);

CREATE INDEX IDP.ats_api_key_idx 
    ON IDP.AUTH_TRUSTED_SERVICES(api_key);

COMMENT ON TABLE IDP.AUTH_TRUSTED_SERVICES 
    IS 'Trusted external services that can authenticate users via pass-through';

PROMPT Created: AUTH_TRUSTED_SERVICES (ats)

-- ============================================================================
-- SECTION 8: AUTH_FEDERATED_IDENTITIES (Alias: afi)
-- Links application users to external identity provider accounts
-- ============================================================================

CREATE TABLE IDP.AUTH_FEDERATED_IDENTITIES
    (afi_id                     NUMBER GENERATED ALWAYS AS IDENTITY
    ,tenant_id                  NUMBER NOT NULL
    ,user_id                    VARCHAR2(100) NOT NULL
    ,afi_aip_id                 NUMBER NOT NULL
    ,external_id                VARCHAR2(500) NOT NULL
    ,external_username          VARCHAR2(255)
    ,external_email             VARCHAR2(255)
    ,linked_date                TIMESTAMP DEFAULT SYSTIMESTAMP
    ,linked_by                  VARCHAR2(100) DEFAULT USER
    ,last_auth_date             TIMESTAMP
    ,last_auth_ip               VARCHAR2(50)
    ,auth_count                 NUMBER DEFAULT 0
    ,is_active                  VARCHAR2(1) DEFAULT 'Y'
    ,created_date               TIMESTAMP DEFAULT SYSTIMESTAMP
    ,created_by                 VARCHAR2(100) DEFAULT USER
    ,modified_date              TIMESTAMP
    ,modified_by                VARCHAR2(100)
    ,CONSTRAINT afi_pk PRIMARY KEY (afi_id)
    ,CONSTRAINT afi_aip_id_fk 
        FOREIGN KEY (afi_aip_id) 
        REFERENCES IDP.AUTH_IDENTITY_PROVIDERS(aip_id)
    ,CONSTRAINT afi_is_active_chk 
        CHECK (is_active IN ('Y','N'))
    ,CONSTRAINT afi_ext_id_uk 
        UNIQUE (tenant_id, afi_aip_id, external_id)
    );

CREATE INDEX IDP.afi_user_idx 
    ON IDP.AUTH_FEDERATED_IDENTITIES(tenant_id, user_id);

CREATE INDEX IDP.afi_aip_id_idx 
    ON IDP.AUTH_FEDERATED_IDENTITIES(afi_aip_id, external_id);

COMMENT ON TABLE IDP.AUTH_FEDERATED_IDENTITIES 
    IS 'Links application users to their external identity provider accounts';

PROMPT Created: AUTH_FEDERATED_IDENTITIES (afi)

-- ============================================================================
-- SECTION 9: AUTH_SSO_SESSIONS (Alias: aso)
-- Active SSO sessions
-- ============================================================================

CREATE TABLE IDP.AUTH_SSO_SESSIONS
    (aso_id                     NUMBER GENERATED ALWAYS AS IDENTITY
    ,tenant_id                  NUMBER NOT NULL
    ,user_id                    VARCHAR2(100) NOT NULL
    ,aso_aip_id                 NUMBER
    ,aso_ats_id                 NUMBER
    ,session_token              VARCHAR2(256) NOT NULL
    ,refresh_token              VARCHAR2(256)
    ,saml_session_index         VARCHAR2(500)
    ,saml_name_id               VARCHAR2(500)
    ,created_date               TIMESTAMP DEFAULT SYSTIMESTAMP
    ,expires_date               TIMESTAMP NOT NULL
    ,last_activity              TIMESTAMP DEFAULT SYSTIMESTAMP
    ,client_ip                  VARCHAR2(50)
    ,user_agent                 VARCHAR2(1000)
    ,is_valid                   VARCHAR2(1) DEFAULT 'Y'
    ,invalidation_reason        VARCHAR2(100)
    ,invalidated_date           TIMESTAMP
    ,CONSTRAINT aso_pk PRIMARY KEY (aso_id)
    ,CONSTRAINT aso_aip_id_fk 
        FOREIGN KEY (aso_aip_id) 
        REFERENCES IDP.AUTH_IDENTITY_PROVIDERS(aip_id)
    ,CONSTRAINT aso_ats_id_fk 
        FOREIGN KEY (aso_ats_id) 
        REFERENCES IDP.AUTH_TRUSTED_SERVICES(ats_id)
    ,CONSTRAINT aso_is_valid_chk 
        CHECK (is_valid IN ('Y','N'))
    ,CONSTRAINT aso_token_uk 
        UNIQUE (session_token)
    );

CREATE INDEX IDP.aso_user_idx 
    ON IDP.AUTH_SSO_SESSIONS(tenant_id, user_id, is_valid);

CREATE INDEX IDP.aso_expires_idx 
    ON IDP.AUTH_SSO_SESSIONS(expires_date, is_valid);

CREATE INDEX IDP.aso_saml_idx 
    ON IDP.AUTH_SSO_SESSIONS(saml_session_index);

CREATE INDEX IDP.aso_aip_id_idx 
    ON IDP.AUTH_SSO_SESSIONS(aso_aip_id);

CREATE INDEX IDP.aso_ats_id_idx 
    ON IDP.AUTH_SSO_SESSIONS(aso_ats_id);

COMMENT ON TABLE IDP.AUTH_SSO_SESSIONS 
    IS 'Active SSO sessions for federated authentication';

PROMPT Created: AUTH_SSO_SESSIONS (aso)

-- ============================================================================
-- SECTION 10: AUTH_FEDERATION_LOG (Alias: afl)
-- Immutable audit log for all authentication events
-- ============================================================================

CREATE TABLE IDP.AUTH_FEDERATION_LOG
    (afl_id                     NUMBER GENERATED ALWAYS AS IDENTITY
    ,tenant_id                  NUMBER
    ,event_timestamp            TIMESTAMP DEFAULT SYSTIMESTAMP NOT NULL
    ,event_type                 VARCHAR2(50) NOT NULL
    ,afl_aip_id                 NUMBER
    ,afl_ats_id                 NUMBER
    ,username                   VARCHAR2(255)
    ,external_id                VARCHAR2(500)
    ,client_ip                  VARCHAR2(50)
    ,user_agent                 VARCHAR2(1000)
    ,request_id                 VARCHAR2(100)
    ,was_successful             VARCHAR2(1)
    ,error_code                 VARCHAR2(50)
    ,error_message              VARCHAR2(2000)
    ,auth_method                VARCHAR2(50)
    ,assertion_id               VARCHAR2(500)
    ,session_duration           NUMBER
    ,attributes_received        CLOB
    ,created_date               TIMESTAMP DEFAULT SYSTIMESTAMP
    ,CONSTRAINT afl_pk PRIMARY KEY (afl_id)
    ,CONSTRAINT afl_event_type_chk 
        CHECK (event_type IN ('AUTH_REQUEST','AUTH_SUCCESS','AUTH_FAILURE',
                              'LOGOUT_REQUEST','LOGOUT_SUCCESS','LOGOUT_FAILURE',
                              'TOKEN_ISSUE','TOKEN_REFRESH','TOKEN_REVOKE',
                              'USER_PROVISION','USER_DEPROVISION','ROLE_SYNC',
                              'CONFIG_CHANGE','CERT_EXPIRY_WARNING'))
    ,CONSTRAINT afl_was_successful_chk 
        CHECK (was_successful IN ('Y','N'))
    );

CREATE INDEX IDP.afl_tenant_idx 
    ON IDP.AUTH_FEDERATION_LOG(tenant_id, event_timestamp DESC);

CREATE INDEX IDP.afl_username_idx 
    ON IDP.AUTH_FEDERATION_LOG(username, event_timestamp DESC);

CREATE INDEX IDP.afl_aip_id_idx 
    ON IDP.AUTH_FEDERATION_LOG(afl_aip_id, event_timestamp DESC);

CREATE INDEX IDP.afl_event_idx 
    ON IDP.AUTH_FEDERATION_LOG(event_type, was_successful, event_timestamp DESC);

COMMENT ON TABLE IDP.AUTH_FEDERATION_LOG 
    IS 'Immutable audit log for all federated authentication events';

-- Protect audit log - append only
CREATE OR REPLACE TRIGGER IDP.afl_protect_trg
BEFORE UPDATE OR DELETE ON IDP.AUTH_FEDERATION_LOG
BEGIN
    RAISE_APPLICATION_ERROR(-20001, 'AUTH_FEDERATION_LOG is append-only for compliance');
END;
/

PROMPT Created: AUTH_FEDERATION_LOG (afl)

-- ============================================================================
-- SECTION 11: VIEWS
-- ============================================================================

CREATE OR REPLACE VIEW IDP.AUTH_PROVIDERS_VW AS
SELECT aip.aip_id
      ,aip.tenant_id
      ,aip.provider_name
      ,aip.provider_code
      ,aip.provider_type
      ,aip.display_name
      ,aip.is_active
      ,aip.is_default
      ,aip.priority_order
      ,aip.endpoint_url
      ,CASE aip.provider_type
           WHEN 'SAML' THEN (SELECT asg.sso_url 
                              FROM IDP.AUTH_SAML_CONFIG asg 
                             WHERE asg.asg_aip_id = aip.aip_id)
           WHEN 'LDAP' THEN (SELECT alg.server_host || ':' || alg.server_port 
                              FROM IDP.AUTH_LDAP_CONFIG alg 
                             WHERE alg.alg_aip_id = aip.aip_id)
           WHEN 'CUSTOM' THEN (SELECT acg.auth_endpoint 
                                FROM IDP.AUTH_CUSTOM_CONFIG acg 
                               WHERE acg.acg_aip_id = aip.aip_id)
           ELSE aip.endpoint_url
       END AS connection_endpoint
      ,(SELECT COUNT(*) 
          FROM IDP.AUTH_FEDERATED_IDENTITIES afi 
         WHERE afi.afi_aip_id = aip.aip_id 
           AND afi.is_active = 'Y') AS linked_users
      ,(SELECT MAX(afi.last_auth_date) 
          FROM IDP.AUTH_FEDERATED_IDENTITIES afi 
         WHERE afi.afi_aip_id = aip.aip_id) AS last_auth_date
      ,aip.created_date
      ,aip.modified_date
  FROM IDP.AUTH_IDENTITY_PROVIDERS aip;

COMMENT ON VIEW IDP.AUTH_PROVIDERS_VW 
    IS 'Provider summary with connection endpoints and usage statistics';

CREATE OR REPLACE VIEW IDP.AUTH_ACTIVE_SESSIONS_VW AS
SELECT aso.aso_id AS session_id
      ,aso.tenant_id
      ,aso.user_id
      ,aso.session_token
      ,aip.provider_name AS auth_provider
      ,aip.provider_type AS auth_type
      ,ats.service_name AS service_provider
      ,aso.created_date AS session_start
      ,aso.expires_date
      ,aso.last_activity
      ,ROUND((CAST(aso.expires_date AS DATE) - SYSDATE) * 24 * 60, 0) AS minutes_remaining
      ,aso.client_ip
      ,aso.is_valid
  FROM IDP.AUTH_SSO_SESSIONS aso
      ,IDP.AUTH_IDENTITY_PROVIDERS aip
      ,IDP.AUTH_TRUSTED_SERVICES ats
 WHERE aso.aso_aip_id = aip.aip_id(+)
   AND aso.aso_ats_id = ats.ats_id(+)
   AND aso.is_valid = 'Y'
   AND aso.expires_date > SYSTIMESTAMP;

COMMENT ON VIEW IDP.AUTH_ACTIVE_SESSIONS_VW 
    IS 'Active session monitoring with provider details';

CREATE OR REPLACE VIEW IDP.AUTH_FEDERATION_STATS_VW AS
SELECT afl.tenant_id
      ,TO_CHAR(afl.event_timestamp, 'YYYY-MM-DD') AS event_date
      ,afl.event_type
      ,afl.was_successful
      ,COUNT(*) AS event_count
  FROM IDP.AUTH_FEDERATION_LOG afl
 WHERE afl.event_timestamp > SYSTIMESTAMP - INTERVAL '30' DAY
 GROUP BY afl.tenant_id
         ,TO_CHAR(afl.event_timestamp, 'YYYY-MM-DD')
         ,afl.event_type
         ,afl.was_successful
 ORDER BY event_date DESC
         ,afl.event_type;

COMMENT ON VIEW IDP.AUTH_FEDERATION_STATS_VW 
    IS 'Authentication statistics aggregated by date and event type';

PROMPT Created: Views (AUTH_PROVIDERS_VW, AUTH_ACTIVE_SESSIONS_VW, AUTH_FEDERATION_STATS_VW)

PROMPT ========================================================================
PROMPT IDP Schema Tables Installation Complete
PROMPT ========================================================================
PROMPT 
PROMPT Tables Created (with aliases):
PROMPT   AUTH_IDENTITY_PROVIDERS   (aip) - Core IdP configuration
PROMPT   AUTH_SAML_CONFIG          (asg) - SAML 2.0 settings
PROMPT   AUTH_SAML_ATTRIBUTE_MAP   (asm) - SAML attribute mappings
PROMPT   AUTH_LDAP_CONFIG          (alg) - LDAP/AD configuration
PROMPT   AUTH_CUSTOM_CONFIG        (acg) - Custom API auth
PROMPT   AUTH_GROUP_ROLE_MAP       (agp) - Group to role mappings
PROMPT   AUTH_TRUSTED_SERVICES     (ats) - Pass-through services
PROMPT   AUTH_FEDERATED_IDENTITIES (afi) - User identity links
PROMPT   AUTH_SSO_SESSIONS         (aso) - Active sessions
PROMPT   AUTH_FEDERATION_LOG       (afl) - Immutable audit log
PROMPT 
PROMPT Views Created:
PROMPT   AUTH_PROVIDERS_VW         - Provider summary
PROMPT   AUTH_ACTIVE_SESSIONS_VW   - Active session monitoring
PROMPT   AUTH_FEDERATION_STATS_VW  - Authentication statistics
PROMPT 
PROMPT ========================================================================

SET DEFINE ON;

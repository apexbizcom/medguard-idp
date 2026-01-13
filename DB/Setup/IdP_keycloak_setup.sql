-- ============================================================================
-- IDP Schema - Keycloak Configuration for MedGuard-DMS
-- ============================================================================
-- Generated: January 2026
-- Keycloak Realm: compliancevault
-- Client ID: medguard-dms
-- ============================================================================

SET DEFINE OFF;
SET SERVEROUTPUT ON SIZE UNLIMITED;

PROMPT ========================================================================
PROMPT Keycloak SAML Configuration for MedGuard-DMS
PROMPT ========================================================================

-- ============================================================================
-- STEP 1: Create Keycloak SAML Identity Provider
-- ============================================================================
PROMPT
PROMPT Step 1: Creating Keycloak SAML Identity Provider...

MERGE INTO IDP.AUTH_IDENTITY_PROVIDERS t
USING (SELECT 1 tenant_id, 'KEYCLOAK_LOCAL' provider_code FROM DUAL) s
ON (t.tenant_id = s.tenant_id AND t.provider_code = s.provider_code)
WHEN MATCHED THEN
    UPDATE SET provider_name = 'Keycloak SSO'
              ,provider_type = 'SAML'
              ,display_name = 'Sign in with Keycloak'
              ,description = 'Local Keycloak SAML 2.0 (Development)'
              ,is_active = 'Y'
              ,is_default = 'Y'
              ,priority_order = 1
              ,modified_date = SYSTIMESTAMP
WHEN NOT MATCHED THEN
    INSERT (tenant_id, provider_name, provider_code, provider_type
           ,display_name, description, is_active, is_default, priority_order)
    VALUES (1, 'Keycloak SSO', 'KEYCLOAK_LOCAL', 'SAML'
           ,'Sign in with Keycloak', 'Local Keycloak SAML 2.0 (Development)'
           ,'Y', 'Y', 1);

PROMPT Created/Updated: Keycloak Identity Provider

-- ============================================================================
-- STEP 2: Configure SAML Settings with Certificate
-- ============================================================================
PROMPT
PROMPT Step 2: Configuring SAML Settings...

DECLARE
    ln_aip_id       NUMBER;
    ln_asg_id       NUMBER;
    lv_certificate  VARCHAR2(4000);
BEGIN
    -- Get the provider ID
    SELECT aip_id
      INTO ln_aip_id
      FROM IDP.AUTH_IDENTITY_PROVIDERS
     WHERE tenant_id = 1
       AND provider_code = 'KEYCLOAK_LOCAL';
    
    -- Build certificate (single string, no line breaks in SQL)
    lv_certificate := '-----BEGIN CERTIFICATE-----' || CHR(10) ||
        'MIICrTCCAZUCBgGbsq41CTANBgkqhkiG9w0BAQsFADAaMRgwFgYDVQQDDA9jb21w' || CHR(10) ||
        'bGlhbmNldmF1bHQwHhcNMjYwMTEyMTQ0NjU5WhcNMzYwMTEyMTQ0ODM5WjAaMRgw' || CHR(10) ||
        'FgYDVQQDDA9jb21wbGlhbmNldmF1bHQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw' || CHR(10) ||
        'ggEKAoIBAQCtUgjEmM/if9CCvbvGjkIGZOso8JcuglVIWzoeKo4/2lmNFcsdf275' || CHR(10) ||
        'vun+UrHtyF2S1KBJg3SJtt06e+NuhczceBTLcZvUkXzbEV7W/AZDshxCpZT0+m/f' || CHR(10) ||
        'c7Zi0Z8DBx4T+bXib7W3TNmMxwFsfAoVwtv3jMlbf7xOR46HfHJ4fGeuOyquNOsZ' || CHR(10) ||
        '0CQNjKuIq7BuGOKPRNTx08VoQ4+29p5WjwPMI2e4c6YaoQKTZ6n4A07ZT1omRekO' || CHR(10) ||
        'U3L3xesPGsCtiCRR8X8nTAnq3AWMQk3u6m0gEEbpDJXdH89ZylMioke7/7QcGXen' || CHR(10) ||
        'NciRWB7R6JeUKFHOlisG8pp+MJykezCXAgMBAAEwDQYJKoZIhvcNAQELBQADggEB' || CHR(10) ||
        'AEY2U9vklmSMi/uZJOjfZSHEGqMgXjf3NO6ZfpPIrFw4tOHuBMc3D3mgEROe425D' || CHR(10) ||
        '1MT91be4waPhKn8xTxKK7hpoEsz94f5+jgQWlB2FTum1a4ODBnNoSTntaSM8L7WD' || CHR(10) ||
        'i93exHGtB87uTPuyoAe7rYDNcouLsLrUUUfi668b6NjgS6NTlr2dwG0kXDsFPVyc' || CHR(10) ||
        'deynwkSOLgCGIWTexXOr7egnJbGi87n1N9i3jR5CiUPnfV2k8fWFTWrVhhnGGy+X' || CHR(10) ||
        'locAAsHuh7zmB/yTnSfSGapWIKG/XRVj8x7TIjEI6lFYwx9Xg3Nazmrmdo/WkwAS' || CHR(10) ||
        '32j8wHNXZJnZEUml1tfw2iA=' || CHR(10) ||
        '-----END CERTIFICATE-----';
    
    -- Check if config exists
    BEGIN
        SELECT asg_id
          INTO ln_asg_id
          FROM IDP.AUTH_SAML_CONFIG
         WHERE asg_aip_id = ln_aip_id;
        
        -- Update existing
        UPDATE IDP.AUTH_SAML_CONFIG
           SET idp_entity_id = 'http://localhost:8180/realms/compliancevault'
              ,sp_entity_id = 'medguard-dms'
              ,sso_url = 'http://localhost:8180/realms/compliancevault/protocol/saml'
              ,slo_url = 'http://localhost:8180/realms/compliancevault/protocol/saml'
              ,idp_certificate = lv_certificate
              ,sso_binding = 'HTTP-POST'
              ,slo_binding = 'HTTP-POST'
              ,want_assertions_signed = 'Y'
              ,sign_authn_requests = 'N'
              ,max_auth_lifetime = 28800
              ,modified_date = SYSTIMESTAMP
         WHERE asg_id = ln_asg_id;
        
        DBMS_OUTPUT.PUT_LINE('Updated: SAML Configuration');
        
    EXCEPTION
        WHEN NO_DATA_FOUND THEN
            -- Insert new
            INSERT INTO IDP.AUTH_SAML_CONFIG
                (asg_aip_id
                ,idp_entity_id
                ,sp_entity_id
                ,sso_url
                ,slo_url
                ,idp_certificate
                ,sso_binding
                ,slo_binding
                ,want_assertions_signed
                ,sign_authn_requests
                ,max_auth_lifetime)
            VALUES
                (ln_aip_id
                ,'http://localhost:8180/realms/compliancevault'
                ,'medguard-dms'
                ,'http://localhost:8180/realms/compliancevault/protocol/saml'
                ,'http://localhost:8180/realms/compliancevault/protocol/saml'
                ,lv_certificate
                ,'HTTP-POST'
                ,'HTTP-POST'
                ,'Y'
                ,'N'
                ,28800);
            
            DBMS_OUTPUT.PUT_LINE('Inserted: SAML Configuration');
    END;
END;
/

PROMPT Created/Updated: SAML Configuration with Certificate

-- ============================================================================
-- STEP 3: Configure Attribute Mappings
-- ============================================================================
PROMPT
PROMPT Step 3: Configuring Attribute Mappings...

DELETE FROM IDP.AUTH_SAML_ATTRIBUTE_MAP
 WHERE asm_asg_id IN (
    SELECT asg.asg_id
      FROM IDP.AUTH_SAML_CONFIG asg
          ,IDP.AUTH_IDENTITY_PROVIDERS aip
     WHERE asg.asg_aip_id = aip.aip_id
       AND aip.tenant_id = 1
       AND aip.provider_code = 'KEYCLOAK_LOCAL'
 );

INSERT INTO IDP.AUTH_SAML_ATTRIBUTE_MAP
    (asm_asg_id, saml_attribute, target_attribute, is_required, transformation)
SELECT asg.asg_id
      ,attr.saml_attr
      ,attr.target_attr
      ,attr.is_required
      ,attr.transform
  FROM IDP.AUTH_SAML_CONFIG asg
      ,IDP.AUTH_IDENTITY_PROVIDERS aip
      ,(
        SELECT 'email' saml_attr, 'EMAIL' target_attr, 'Y' is_required, 'LOWERCASE' transform FROM DUAL
        UNION ALL
        SELECT 'firstName', 'FIRST_NAME', 'N', 'NONE' FROM DUAL
        UNION ALL
        SELECT 'lastName', 'LAST_NAME', 'N', 'NONE' FROM DUAL
        UNION ALL
        SELECT 'groups', 'GROUPS', 'N', 'NONE' FROM DUAL
       ) attr
 WHERE asg.asg_aip_id = aip.aip_id
   AND aip.tenant_id = 1
   AND aip.provider_code = 'KEYCLOAK_LOCAL';

PROMPT Created: 4 Attribute Mappings

-- ============================================================================
-- STEP 4: Configure Role Mappings
-- ============================================================================
PROMPT
PROMPT Step 4: Configuring Role Mappings...

DELETE FROM IDP.AUTH_GROUP_ROLE_MAP
 WHERE agp_aip_id IN (
    SELECT aip.aip_id
      FROM IDP.AUTH_IDENTITY_PROVIDERS aip
     WHERE aip.tenant_id = 1
       AND aip.provider_code = 'KEYCLOAK_LOCAL'
 );

INSERT INTO IDP.AUTH_GROUP_ROLE_MAP
    (agp_aip_id, external_group, target_role_id, target_role_name, auto_provision)
SELECT aip.aip_id, grp.keycloak_group, grp.role_id, grp.role_name, 'Y'
  FROM IDP.AUTH_IDENTITY_PROVIDERS aip
      ,(
        SELECT 'ComplianceVault-Admins' keycloak_group, 1 role_id, 'ADMIN' role_name FROM DUAL
        UNION ALL
        SELECT 'ComplianceVault-QualityManagers', 2, 'QUALITY_MANAGER' FROM DUAL
        UNION ALL
        SELECT 'ComplianceVault-Users', 3, 'USER' FROM DUAL
       ) grp
 WHERE aip.tenant_id = 1
   AND aip.provider_code = 'KEYCLOAK_LOCAL';

PROMPT Created: 3 Role Mappings

-- ============================================================================
-- STEP 5: Configure MFA Policy
-- ============================================================================
PROMPT
PROMPT Step 5: Configuring MFA Policy...

MERGE INTO IDP.AUTH_MFA_CONFIG t
USING (SELECT 1 tenant_id FROM DUAL) s
ON (t.tenant_id = s.tenant_id)
WHEN MATCHED THEN
    UPDATE SET mfa_required = 'N'
              ,mfa_required_roles = 'ADMIN'
              ,totp_issuer = 'MedGuard-DMS'
              ,remember_device_enabled = 'Y'
              ,remember_device_days = 30
              ,modified_date = SYSTIMESTAMP
WHEN NOT MATCHED THEN
    INSERT (tenant_id, mfa_required, mfa_required_roles, totp_issuer
           ,remember_device_enabled, remember_device_days
           ,max_failed_attempts, lockout_duration_minutes)
    VALUES (1, 'N', 'ADMIN', 'MedGuard-DMS', 'Y', 30, 5, 15);

PROMPT Created/Updated: MFA Configuration

COMMIT;

-- ============================================================================
-- VERIFICATION
-- ============================================================================
PROMPT
PROMPT ========================================================================
PROMPT Configuration Verification
PROMPT ========================================================================

PROMPT
PROMPT Identity Provider:
SELECT provider_code, provider_type, is_active, is_default
  FROM IDP.AUTH_IDENTITY_PROVIDERS
 WHERE tenant_id = 1 AND provider_code = 'KEYCLOAK_LOCAL';

PROMPT
PROMPT SAML Configuration:
SELECT asg.idp_entity_id
      ,asg.sp_entity_id
      ,asg.sso_url
      ,CASE WHEN asg.idp_certificate IS NOT NULL 
            THEN 'Certificate Configured' 
            ELSE 'MISSING' END as cert_status
  FROM IDP.AUTH_SAML_CONFIG asg
      ,IDP.AUTH_IDENTITY_PROVIDERS aip
 WHERE asg.asg_aip_id = aip.aip_id
   AND aip.provider_code = 'KEYCLOAK_LOCAL';

PROMPT
PROMPT Attribute Mappings:
SELECT asm.saml_attribute, asm.target_attribute, asm.is_required
  FROM IDP.AUTH_SAML_ATTRIBUTE_MAP asm
      ,IDP.AUTH_SAML_CONFIG asg
      ,IDP.AUTH_IDENTITY_PROVIDERS aip
 WHERE asm.asm_asg_id = asg.asg_id
   AND asg.asg_aip_id = aip.aip_id
   AND aip.provider_code = 'KEYCLOAK_LOCAL';

PROMPT
PROMPT ========================================================================
PROMPT Configuration Complete!
PROMPT ========================================================================
PROMPT
PROMPT Next: Create the SAML ACS page in your APEX application
PROMPT
PROMPT Test URL (after APEX setup):
PROMPT http://localhost:8180/realms/compliancevault/protocol/saml/clients/medguard-dms
PROMPT
PROMPT ========================================================================

SET DEFINE ON;

/*
========================================================================
Keycloak SAML Configuration for MedGuard-DMS
========================================================================

Step 1: Creating Keycloak SAML Identity Provider...

1 row merged.

Created/Updated: Keycloak Identity Provider

Step 2: Configuring SAML Settings...
Inserted: SAML Configuration


PL/SQL procedure successfully completed.

Created/Updated: SAML Configuration with Certificate

Step 3: Configuring Attribute Mappings...

0 rows deleted.


4 rows inserted.

Created: 4 Attribute Mappings

Step 4: Configuring Role Mappings...

3 rows deleted.


3 rows inserted.

Created: 3 Role Mappings

Step 5: Configuring MFA Policy...

1 row merged.

Created/Updated: MFA Configuration

Commit complete.


========================================================================
Configuration Verification
========================================================================

Identity Provider:
>>Query Run In:Query Result

SAML Configuration:
>>Query Run In:Query Result 1

Attribute Mappings:
>>Query Run In:Query Result 2

========================================================================
Configuration Complete!
========================================================================

Next: Create the SAML ACS page in your APEX application

Test URL (after APEX setup):
http://localhost:8180/realms/compliancevault/protocol/saml/clients/medguard-dms

========================================================================

*/
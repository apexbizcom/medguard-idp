SET SCAN OFF
SET DEFINE OFF

CREATE OR REPLACE PACKAGE IDP.mfa_auth_pkg
AUTHID CURRENT_USER
AS
    -- ========================================================================
    -- Package: mfa_auth_pkg
    -- Schema:  IDP
    -- Purpose: TOTP-based Multi-Factor Authentication
    --          Compatible with Microsoft Authenticator, Google Authenticator,
    --          Authy, 1Password, and other RFC 6238 compliant apps
    -- Version: 1.0
    -- ========================================================================
    
    -- ========================================================================
    -- CONSTANTS
    -- ========================================================================
    gc_challenge_totp       CONSTANT VARCHAR2(20) := 'TOTP';
    gc_challenge_backup     CONSTANT VARCHAR2(20) := 'BACKUP_CODE';
    
    gc_status_pending       CONSTANT VARCHAR2(20) := 'PENDING';
    gc_status_verified      CONSTANT VARCHAR2(20) := 'VERIFIED';
    gc_status_disabled      CONSTANT VARCHAR2(20) := 'DISABLED';
    gc_status_suspended     CONSTANT VARCHAR2(20) := 'SUSPENDED';
    
    -- ========================================================================
    -- TYPE DEFINITIONS
    -- ========================================================================
    
    TYPE t_mfa_status IS RECORD
        (is_enrolled        BOOLEAN
        ,enrollment_status  VARCHAR2(20)
        ,enrolled_date      TIMESTAMP
        ,last_used_date     TIMESTAMP
        ,use_count          NUMBER
        ,backup_codes_left  NUMBER
        ,trusted_devices    NUMBER
        ,is_required        BOOLEAN
        ,in_grace_period    BOOLEAN
        ,grace_days_left    NUMBER
        );
    
    TYPE t_backup_code_list IS TABLE OF VARCHAR2(20) INDEX BY PLS_INTEGER;
    
    -- ========================================================================
    -- ENROLLMENT FUNCTIONS
    -- ========================================================================
    
    -- Begin MFA enrollment - returns TOTP secret and provisioning URI
    FUNCTION begin_enrollment
        (pn_tenant_id       IN  NUMBER
        ,pv_user_id         IN  VARCHAR2
        ,pv_user_email      IN  VARCHAR2
        ,pv_totp_secret     OUT VARCHAR2
        ,pv_provisioning_uri OUT VARCHAR2
        )
    RETURN BOOLEAN;
    
    -- Complete enrollment by verifying first TOTP code
    FUNCTION verify_enrollment
        (pn_tenant_id       IN  NUMBER
        ,pv_user_id         IN  VARCHAR2
        ,pv_totp_code       IN  VARCHAR2
        ,pt_backup_codes    OUT t_backup_code_list
        )
    RETURN BOOLEAN;
    
    -- ========================================================================
    -- VERIFICATION FUNCTIONS
    -- ========================================================================
    
    -- Verify TOTP code during login
    FUNCTION verify_totp
        (pn_tenant_id       IN  NUMBER
        ,pv_user_id         IN  VARCHAR2
        ,pv_totp_code       IN  VARCHAR2
        ,pv_client_ip       IN  VARCHAR2 DEFAULT NULL
        ,pv_session_id      IN  VARCHAR2 DEFAULT NULL
        )
    RETURN BOOLEAN;
    
    -- Verify backup code (one-time use)
    FUNCTION verify_backup_code
        (pn_tenant_id       IN  NUMBER
        ,pv_user_id         IN  VARCHAR2
        ,pv_backup_code     IN  VARCHAR2
        ,pv_client_ip       IN  VARCHAR2 DEFAULT NULL
        )
    RETURN BOOLEAN;
    
    -- ========================================================================
    -- BACKUP CODE MANAGEMENT
    -- ========================================================================
    
    -- Generate new set of backup codes (invalidates existing)
    FUNCTION regenerate_backup_codes
        (pn_tenant_id       IN  NUMBER
        ,pv_user_id         IN  VARCHAR2
        ,pt_backup_codes    OUT t_backup_code_list
        )
    RETURN BOOLEAN;
    
    -- Get count of remaining backup codes
    FUNCTION get_backup_code_count
        (pn_tenant_id       IN  NUMBER
        ,pv_user_id         IN  VARCHAR2
        )
    RETURN NUMBER;
    PRAGMA RESTRICT_REFERENCES(get_backup_code_count, WNDS);
    
    -- ========================================================================
    -- TRUSTED DEVICE MANAGEMENT
    -- ========================================================================
    
    -- Mark device as trusted (Remember this device)
    FUNCTION trust_device
        (pn_tenant_id       IN  NUMBER
        ,pv_user_id         IN  VARCHAR2
        ,pv_device_name     IN  VARCHAR2 DEFAULT NULL
        ,pv_user_agent      IN  VARCHAR2 DEFAULT NULL
        ,pv_client_ip       IN  VARCHAR2 DEFAULT NULL
        ,pv_device_token    OUT VARCHAR2
        )
    RETURN BOOLEAN;
    
    -- Check if device is trusted
    FUNCTION is_device_trusted
        (pn_tenant_id       IN  NUMBER
        ,pv_user_id         IN  VARCHAR2
        ,pv_device_token    IN  VARCHAR2
        )
    RETURN BOOLEAN;
    
    -- Revoke a specific trusted device
    PROCEDURE revoke_device
        (pn_tenant_id       IN  NUMBER
        ,pv_user_id         IN  VARCHAR2
        ,pn_amt_id          IN  NUMBER
        );
    
    -- Revoke all trusted devices for user
    PROCEDURE revoke_all_devices
        (pn_tenant_id       IN  NUMBER
        ,pv_user_id         IN  VARCHAR2
        );
    
    -- Get list of trusted devices
    FUNCTION get_trusted_devices
        (pn_tenant_id       IN  NUMBER
        ,pv_user_id         IN  VARCHAR2
        ,pc_devices         OUT SYS_REFCURSOR
        )
    RETURN NUMBER;
    
    -- ========================================================================
    -- STATUS & POLICY FUNCTIONS
    -- ========================================================================
    
    -- Check if MFA is required for user
    FUNCTION is_mfa_required
        (pn_tenant_id       IN  NUMBER
        ,pv_user_id         IN  VARCHAR2
        ,pv_user_roles      IN  VARCHAR2 DEFAULT NULL
        )
    RETURN BOOLEAN;
    
    -- Get complete MFA status for user
    FUNCTION get_mfa_status
        (pn_tenant_id       IN  NUMBER
        ,pv_user_id         IN  VARCHAR2
        )
    RETURN t_mfa_status;
    
    -- Check if user is in lockout
    FUNCTION is_user_locked
        (pn_tenant_id       IN  NUMBER
        ,pv_user_id         IN  VARCHAR2
        )
    RETURN BOOLEAN;
    
    -- ========================================================================
    -- ADMIN FUNCTIONS
    -- ========================================================================
    
    -- Disable MFA for user (admin function)
    PROCEDURE disable_mfa
        (pn_tenant_id       IN  NUMBER
        ,pv_user_id         IN  VARCHAR2
        ,pv_disabled_by     IN  VARCHAR2
        ,pv_reason          IN  VARCHAR2 DEFAULT NULL
        );
    
    -- Re-enable MFA for user
    PROCEDURE enable_mfa
        (pn_tenant_id       IN  NUMBER
        ,pv_user_id         IN  VARCHAR2
        );
    
    -- Reset MFA (remove enrollment, user must re-enroll)
    PROCEDURE reset_mfa
        (pn_tenant_id       IN  NUMBER
        ,pv_user_id         IN  VARCHAR2
        ,pv_reset_by        IN  VARCHAR2
        );
    
    -- ========================================================================
    -- AUDIT FUNCTIONS
    -- ========================================================================
    
    -- Log MFA challenge attempt
    PROCEDURE log_challenge
        (pn_tenant_id       IN  NUMBER
        ,pv_user_id         IN  VARCHAR2
        ,pv_challenge_type  IN  VARCHAR2
        ,pb_was_successful  IN  BOOLEAN
        ,pv_failure_reason  IN  VARCHAR2 DEFAULT NULL
        ,pv_client_ip       IN  VARCHAR2 DEFAULT NULL
        ,pv_user_agent      IN  VARCHAR2 DEFAULT NULL
        ,pv_session_id      IN  VARCHAR2 DEFAULT NULL
        );
    
    -- Get MFA challenge history
    FUNCTION get_challenge_history
        (pn_tenant_id       IN  NUMBER
        ,pv_user_id         IN  VARCHAR2
        ,pn_days_back       IN  NUMBER DEFAULT 30
        ,pc_history         OUT SYS_REFCURSOR
        )
    RETURN NUMBER;
    
    -- ========================================================================
    -- HELPER FUNCTIONS
    -- ========================================================================
    
    -- Generate TOTP code for testing (internal use)
    FUNCTION generate_totp
        (pv_secret          IN  VARCHAR2
        ,pn_time_step       IN  NUMBER DEFAULT NULL
        )
    RETURN VARCHAR2;
    
    -- Base32 encode (for displaying secret to user)
    FUNCTION base32_encode
        (po_data            IN  RAW
        )
    RETURN VARCHAR2;
    PRAGMA RESTRICT_REFERENCES(base32_encode, WNDS, RNPS);
    
    -- Base32 decode
    FUNCTION base32_decode
        (pv_data            IN  VARCHAR2
        )
    RETURN RAW;
    PRAGMA RESTRICT_REFERENCES(base32_decode, WNDS, RNPS);

END mfa_auth_pkg;
/

CREATE OR REPLACE PACKAGE BODY IDP.mfa_auth_pkg
AS
    -- ========================================================================
    -- PRIVATE CONSTANTS
    -- ========================================================================
    gc_base32_alphabet  CONSTANT VARCHAR2(32) := 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    gc_totp_digits      CONSTANT NUMBER := 6;
    gc_totp_period      CONSTANT NUMBER := 30;
    gc_totp_window      CONSTANT NUMBER := 1;
    
    -- ========================================================================
    -- base32_encode
    -- ========================================================================
    FUNCTION base32_encode
        (po_data            IN  RAW
        )
    RETURN VARCHAR2 IS
        lv_result       VARCHAR2(4000) := '';
        lv_hex          VARCHAR2(4000);
        ln_bits         NUMBER := 0;
        ln_val          NUMBER := 0;
        ln_len          NUMBER;
    BEGIN
        lv_hex := RAWTOHEX(po_data);
        ln_len := LENGTH(lv_hex);
        
        FOR ln_i IN 1..ln_len LOOP
            ln_val := ln_val * 16 + TO_NUMBER(SUBSTR(lv_hex, ln_i, 1), 'X');
            ln_bits := ln_bits + 4;
            
            IF ln_bits >= 5 THEN
                ln_bits := ln_bits - 5;
                lv_result := lv_result || SUBSTR(gc_base32_alphabet
                            ,FLOOR(ln_val / POWER(2, ln_bits)) + 1, 1);
                ln_val := MOD(ln_val, POWER(2, ln_bits));
            END IF;
        END LOOP;
        
        IF ln_bits > 0 THEN
            lv_result := lv_result || SUBSTR(gc_base32_alphabet
                        ,FLOOR(ln_val * POWER(2, 5 - ln_bits)) + 1, 1);
        END IF;
        
        RETURN lv_result;
    END base32_encode;
    
    -- ========================================================================
    -- base32_decode
    -- ========================================================================
    FUNCTION base32_decode
        (pv_data            IN  VARCHAR2
        )
    RETURN RAW IS
        lv_input        VARCHAR2(4000);
        lv_hex          VARCHAR2(4000) := '';
        ln_bits         NUMBER := 0;
        ln_val          NUMBER := 0;
        ln_char_val     NUMBER;
    BEGIN
        lv_input := UPPER(REPLACE(REPLACE(pv_data, '=', ''), ' ', ''));
        
        FOR ln_i IN 1..LENGTH(lv_input) LOOP
            ln_char_val := INSTR(gc_base32_alphabet, SUBSTR(lv_input, ln_i, 1)) - 1;
            IF ln_char_val >= 0 THEN
                ln_val := ln_val * 32 + ln_char_val;
                ln_bits := ln_bits + 5;
                
                IF ln_bits >= 8 THEN
                    ln_bits := ln_bits - 8;
                    lv_hex := lv_hex || TO_CHAR(FLOOR(ln_val / POWER(2, ln_bits)), 'FM0X');
                    ln_val := MOD(ln_val, POWER(2, ln_bits));
                END IF;
            END IF;
        END LOOP;
        
        RETURN HEXTORAW(lv_hex);
    END base32_decode;
    
    -- ========================================================================
    -- generate_totp
    -- ========================================================================
    FUNCTION generate_totp
        (pv_secret          IN  VARCHAR2
        ,pn_time_step       IN  NUMBER DEFAULT NULL
        )
    RETURN VARCHAR2 IS
        lo_key          RAW(64);
        lo_counter      RAW(8);
        lo_hash         RAW(20);
        ln_time_step    NUMBER;
        ln_offset       NUMBER;
        ln_binary       NUMBER;
        ln_otp          NUMBER;
    BEGIN
        lo_key := base32_decode(pv_secret);
        
        IF pn_time_step IS NULL THEN
            ln_time_step := FLOOR((SYSDATE - DATE '1970-01-01') * 86400 / gc_totp_period);
        ELSE
            ln_time_step := pn_time_step;
        END IF;
        
        lo_counter := HEXTORAW(LPAD(TO_CHAR(ln_time_step, 'FMXXXXXXXXXXXXXXXX'), 16, '0'));
        
        lo_hash := DBMS_CRYPTO.MAC(
            src => lo_counter
           ,typ => DBMS_CRYPTO.HMAC_SH1
           ,key => lo_key
        );
        
        ln_offset := TO_NUMBER(SUBSTR(RAWTOHEX(lo_hash), 40, 1), 'X');
        ln_binary := TO_NUMBER(SUBSTR(RAWTOHEX(lo_hash), ln_offset * 2 + 1, 8), 'XXXXXXXX');
        ln_binary := BITAND(ln_binary, 2147483647);
        ln_otp := MOD(ln_binary, POWER(10, gc_totp_digits));
        
        RETURN LPAD(TO_CHAR(ln_otp), gc_totp_digits, '0');
    END generate_totp;
    
    -- ========================================================================
    -- get_tenant_config (private)
    -- ========================================================================
    FUNCTION get_tenant_config
        (pn_tenant_id       IN  NUMBER
        )
    RETURN IDP.AUTH_MFA_CONFIG%ROWTYPE IS
        lt_config   IDP.AUTH_MFA_CONFIG%ROWTYPE;
    BEGIN
        SELECT *
          INTO lt_config
          FROM IDP.AUTH_MFA_CONFIG amc
         WHERE amc.tenant_id = pn_tenant_id;
        RETURN lt_config;
    EXCEPTION
        WHEN NO_DATA_FOUND THEN
            lt_config.totp_issuer := 'ComplianceVault';
            lt_config.totp_digits := 6;
            lt_config.totp_period := 30;
            lt_config.backup_code_count := 10;
            lt_config.max_failed_attempts := 5;
            lt_config.lockout_duration_minutes := 15;
            lt_config.remember_device_days := 30;
            lt_config.remember_device_enabled := 'Y';
            RETURN lt_config;
    END get_tenant_config;
    
    -- ========================================================================
    -- log_challenge
    -- ========================================================================
    PROCEDURE log_challenge
        (pn_tenant_id       IN  NUMBER
        ,pv_user_id         IN  VARCHAR2
        ,pv_challenge_type  IN  VARCHAR2
        ,pb_was_successful  IN  BOOLEAN
        ,pv_failure_reason  IN  VARCHAR2 DEFAULT NULL
        ,pv_client_ip       IN  VARCHAR2 DEFAULT NULL
        ,pv_user_agent      IN  VARCHAR2 DEFAULT NULL
        ,pv_session_id      IN  VARCHAR2 DEFAULT NULL
        )
    IS
        PRAGMA AUTONOMOUS_TRANSACTION;
        lv_was_successful   VARCHAR2(1);
    BEGIN
        lv_was_successful := CASE WHEN pb_was_successful THEN 'Y' ELSE 'N' END;
        
        INSERT INTO IDP.AUTH_MFA_CHALLENGES
            (tenant_id, user_id, challenge_type, challenge_timestamp
            ,was_successful, failure_reason, ip_address, user_agent, session_id)
        VALUES
            (pn_tenant_id, pv_user_id, pv_challenge_type, SYSTIMESTAMP
            ,lv_was_successful, pv_failure_reason, pv_client_ip, pv_user_agent, pv_session_id);
        COMMIT;
    EXCEPTION
        WHEN OTHERS THEN
            ROLLBACK;
    END log_challenge;
    
    -- ========================================================================
    -- is_user_locked
    -- ========================================================================
    FUNCTION is_user_locked
        (pn_tenant_id       IN  NUMBER
        ,pv_user_id         IN  VARCHAR2
        )
    RETURN BOOLEAN IS
        lt_config       IDP.AUTH_MFA_CONFIG%ROWTYPE;
        ln_failed_count NUMBER := 0;
    BEGIN
        lt_config := get_tenant_config(pn_tenant_id);
        
        SELECT COUNT(*)
          INTO ln_failed_count
          FROM IDP.AUTH_MFA_CHALLENGES amh
         WHERE amh.tenant_id = pn_tenant_id
           AND amh.user_id = pv_user_id
           AND amh.was_successful = 'N'
           AND amh.challenge_timestamp > SYSTIMESTAMP 
               - NUMTODSINTERVAL(lt_config.lockout_duration_minutes, 'MINUTE');
        
        RETURN ln_failed_count >= lt_config.max_failed_attempts;
    END is_user_locked;
    
    -- ========================================================================
    -- begin_enrollment
    -- ========================================================================
    FUNCTION begin_enrollment
        (pn_tenant_id       IN  NUMBER
        ,pv_user_id         IN  VARCHAR2
        ,pv_user_email      IN  VARCHAR2
        ,pv_totp_secret     OUT VARCHAR2
        ,pv_provisioning_uri OUT VARCHAR2
        )
    RETURN BOOLEAN IS
        lt_config       IDP.AUTH_MFA_CONFIG%ROWTYPE;
        lo_secret       RAW(20);
        lo_salt         RAW(32);
        lo_encrypted    RAW(256);
        lv_secret_b32   VARCHAR2(100);
        lo_key          RAW(32);
    BEGIN
        lt_config := get_tenant_config(pn_tenant_id);
        
        lo_secret := DBMS_CRYPTO.RANDOMBYTES(20);
        lo_salt := DBMS_CRYPTO.RANDOMBYTES(32);
        lv_secret_b32 := base32_encode(lo_secret);
        
        lo_key := DBMS_CRYPTO.HASH(lo_salt, DBMS_CRYPTO.HASH_SH256);
        lo_encrypted := DBMS_CRYPTO.ENCRYPT(
            src => lo_secret
           ,typ => DBMS_CRYPTO.ENCRYPT_AES256 + DBMS_CRYPTO.CHAIN_CBC + DBMS_CRYPTO.PAD_PKCS5
           ,key => lo_key
        );
        
        MERGE INTO IDP.AUTH_MFA_ENROLLMENT t
        USING (SELECT pn_tenant_id tn, pv_user_id ui FROM DUAL) s
        ON (t.tenant_id = s.tn AND t.user_id = s.ui)
        WHEN MATCHED THEN
            UPDATE SET totp_secret_encrypted = lo_encrypted
                      ,totp_secret_salt = lo_salt
                      ,enrollment_status = gc_status_pending
                      ,enrolled_date = SYSTIMESTAMP
                      ,verified_date = NULL
                      ,modified_date = SYSTIMESTAMP
        WHEN NOT MATCHED THEN
            INSERT (tenant_id, user_id, totp_secret_encrypted, totp_secret_salt
                   ,enrollment_status, enrolled_date)
            VALUES (s.tn, s.ui, lo_encrypted, lo_salt, gc_status_pending, SYSTIMESTAMP);
        
        pv_totp_secret := lv_secret_b32;
        pv_provisioning_uri := 'otpauth://totp/' 
            || UTL_URL.ESCAPE(lt_config.totp_issuer, TRUE, 'UTF-8') || ':' 
            || UTL_URL.ESCAPE(pv_user_email, TRUE, 'UTF-8')
            || '?secret=' || lv_secret_b32
            || '&issuer=' || UTL_URL.ESCAPE(lt_config.totp_issuer, TRUE, 'UTF-8')
            || '&algorithm=SHA1&digits=6&period=30';
        
        COMMIT;
        RETURN TRUE;
    EXCEPTION
        WHEN OTHERS THEN
            ROLLBACK;
            RETURN FALSE;
    END begin_enrollment;
    
    -- ========================================================================
    -- verify_enrollment
    -- ========================================================================
    FUNCTION verify_enrollment
        (pn_tenant_id       IN  NUMBER
        ,pv_user_id         IN  VARCHAR2
        ,pv_totp_code       IN  VARCHAR2
        ,pt_backup_codes    OUT t_backup_code_list
        )
    RETURN BOOLEAN IS
        lo_encrypted    RAW(256);
        lo_salt         RAW(32);
        lo_key          RAW(32);
        lo_secret       RAW(20);
        lv_secret_b32   VARCHAR2(100);
        lv_expected     VARCHAR2(10);
        ln_time_step    NUMBER;
        lb_valid        BOOLEAN := FALSE;
        ln_ame_id       NUMBER;
    BEGIN
        SELECT ame.ame_id, ame.totp_secret_encrypted, ame.totp_secret_salt
          INTO ln_ame_id, lo_encrypted, lo_salt
          FROM IDP.AUTH_MFA_ENROLLMENT ame
         WHERE ame.tenant_id = pn_tenant_id
           AND ame.user_id = pv_user_id
           AND ame.enrollment_status = gc_status_pending;
        
        lo_key := DBMS_CRYPTO.HASH(lo_salt, DBMS_CRYPTO.HASH_SH256);
        lo_secret := DBMS_CRYPTO.DECRYPT(
            src => lo_encrypted
           ,typ => DBMS_CRYPTO.ENCRYPT_AES256 + DBMS_CRYPTO.CHAIN_CBC + DBMS_CRYPTO.PAD_PKCS5
           ,key => lo_key
        );
        lv_secret_b32 := base32_encode(lo_secret);
        
        ln_time_step := FLOOR((SYSDATE - DATE '1970-01-01') * 86400 / gc_totp_period);
        FOR ln_i IN -gc_totp_window..gc_totp_window LOOP
            lv_expected := generate_totp(lv_secret_b32, ln_time_step + ln_i);
            IF pv_totp_code = lv_expected THEN
                lb_valid := TRUE;
                EXIT;
            END IF;
        END LOOP;
        
        IF NOT lb_valid THEN
            log_challenge(pn_tenant_id, pv_user_id, gc_challenge_totp, FALSE, 'INVALID_CODE');
            RETURN FALSE;
        END IF;
        
        UPDATE IDP.AUTH_MFA_ENROLLMENT
           SET enrollment_status = gc_status_verified
              ,verified_date = SYSTIMESTAMP
              ,last_used_date = SYSTIMESTAMP
              ,use_count = 1
         WHERE ame_id = ln_ame_id;
        
        DELETE FROM IDP.AUTH_MFA_BACKUP_CODES WHERE amb_ame_id = ln_ame_id;
        
        FOR ln_i IN 1..10 LOOP
            pt_backup_codes(ln_i) := SUBSTR(RAWTOHEX(DBMS_CRYPTO.RANDOMBYTES(4)), 1, 4) || '-' ||
                                     SUBSTR(RAWTOHEX(DBMS_CRYPTO.RANDOMBYTES(4)), 1, 4);
            
            INSERT INTO IDP.AUTH_MFA_BACKUP_CODES (amb_ame_id, code_hash)
            VALUES (ln_ame_id, RAWTOHEX(DBMS_CRYPTO.HASH(
                UTL_RAW.CAST_TO_RAW(REPLACE(pt_backup_codes(ln_i), '-', ''))
               ,DBMS_CRYPTO.HASH_SH256)));
        END LOOP;
        
        log_challenge(pn_tenant_id, pv_user_id, gc_challenge_totp, TRUE);
        
         -- Bridge enrollment completion to DMS SOC2
         BEGIN
             IDP.idp_dms_bridge_pkg.bridge_mfa_enrollment(
                 pn_tenant_id        => pn_tenant_id
                ,pv_user_id          => pv_user_id
                ,pv_action           => 'COMPLETED'
                ,pv_ip_address       => NULL  -- Not available in this function
             );
         EXCEPTION
             WHEN OTHERS THEN NULL;
         END;
        
        COMMIT;
        RETURN TRUE;
    EXCEPTION
        WHEN NO_DATA_FOUND THEN
            RETURN FALSE;
        WHEN OTHERS THEN
            ROLLBACK;
            RETURN FALSE;
    END verify_enrollment;
    
    -- ========================================================================
    -- verify_totp
    -- ========================================================================
    FUNCTION verify_totp
        (pn_tenant_id       IN  NUMBER
        ,pv_user_id         IN  VARCHAR2
        ,pv_totp_code       IN  VARCHAR2
        ,pv_client_ip       IN  VARCHAR2 DEFAULT NULL
        ,pv_session_id      IN  VARCHAR2 DEFAULT NULL
        )
    RETURN BOOLEAN IS
        lo_encrypted    RAW(256);
        lo_salt         RAW(32);
        lo_key          RAW(32);
        lo_secret       RAW(20);
        lv_secret_b32   VARCHAR2(100);
        lv_expected     VARCHAR2(10);
        ln_time_step    NUMBER;
        lb_valid        BOOLEAN := FALSE;
        ln_ame_id       NUMBER;
    BEGIN
        IF is_user_locked(pn_tenant_id, pv_user_id) THEN
            log_challenge(pn_tenant_id, pv_user_id, gc_challenge_totp, FALSE
                         ,'ACCOUNT_LOCKED', pv_client_ip, NULL, pv_session_id);
            RETURN FALSE;
        END IF;
        
        SELECT ame.ame_id, ame.totp_secret_encrypted, ame.totp_secret_salt
          INTO ln_ame_id, lo_encrypted, lo_salt
          FROM IDP.AUTH_MFA_ENROLLMENT ame
         WHERE ame.tenant_id = pn_tenant_id
           AND ame.user_id = pv_user_id
           AND ame.enrollment_status = gc_status_verified;
        
        lo_key := DBMS_CRYPTO.HASH(lo_salt, DBMS_CRYPTO.HASH_SH256);
        lo_secret := DBMS_CRYPTO.DECRYPT(
            src => lo_encrypted
           ,typ => DBMS_CRYPTO.ENCRYPT_AES256 + DBMS_CRYPTO.CHAIN_CBC + DBMS_CRYPTO.PAD_PKCS5
           ,key => lo_key
        );
        lv_secret_b32 := base32_encode(lo_secret);
        
        ln_time_step := FLOOR((SYSDATE - DATE '1970-01-01') * 86400 / gc_totp_period);
        FOR ln_i IN -gc_totp_window..gc_totp_window LOOP
            lv_expected := generate_totp(lv_secret_b32, ln_time_step + ln_i);
            IF pv_totp_code = lv_expected THEN
                lb_valid := TRUE;
                EXIT;
            END IF;
        END LOOP;
        
        IF lb_valid THEN
            UPDATE IDP.AUTH_MFA_ENROLLMENT
               SET last_used_date = SYSTIMESTAMP, use_count = use_count + 1
             WHERE ame_id = ln_ame_id;
            log_challenge(pn_tenant_id, pv_user_id, gc_challenge_totp, TRUE, NULL, pv_client_ip, NULL, pv_session_id);

            -- Bridge MFA verification to DMS SOC2
            BEGIN
               IDP.idp_dms_bridge_pkg.bridge_mfa_challenge(
                   pn_tenant_id        => pn_tenant_id
                  ,pv_user_id          => pv_user_id
                  ,pv_challenge_type   => 'TOTP'
                  ,pb_was_successful   => TRUE
                  ,pv_ip_address       => pv_client_ip
               );
            EXCEPTION
               WHEN OTHERS THEN NULL;
            END;
            
            COMMIT;
            RETURN TRUE;
        ELSE
            log_challenge(pn_tenant_id, pv_user_id, gc_challenge_totp, FALSE, 'INVALID_CODE', pv_client_ip, NULL, pv_session_id);
            
            -- Bridge MFA failure to DMS SOC2
            BEGIN
               IDP.idp_dms_bridge_pkg.bridge_mfa_challenge(
                   pn_tenant_id        => pn_tenant_id
                  ,pv_user_id          => pv_user_id
                  ,pv_challenge_type   => 'TOTP'
                  ,pb_was_successful   => FALSE
                  ,pv_ip_address       => pv_client_ip
               );
            EXCEPTION
               WHEN OTHERS THEN NULL;
            END;

            RETURN FALSE;
        END IF;
    EXCEPTION
        WHEN NO_DATA_FOUND THEN
            log_challenge(pn_tenant_id, pv_user_id, gc_challenge_totp, FALSE, 'NOT_ENROLLED', pv_client_ip, NULL, pv_session_id);
            RETURN FALSE;
    END verify_totp;
    
    -- ========================================================================
    -- verify_backup_code
    -- ========================================================================
    FUNCTION verify_backup_code
        (pn_tenant_id       IN  NUMBER
        ,pv_user_id         IN  VARCHAR2
        ,pv_backup_code     IN  VARCHAR2
        ,pv_client_ip       IN  VARCHAR2 DEFAULT NULL
        )
    RETURN BOOLEAN IS
        lv_code_hash    VARCHAR2(256);
        ln_ame_id       NUMBER;
        ln_amb_id       NUMBER;
    BEGIN
        IF is_user_locked(pn_tenant_id, pv_user_id) THEN
            RETURN FALSE;
        END IF;
        
        lv_code_hash := RAWTOHEX(DBMS_CRYPTO.HASH(
            UTL_RAW.CAST_TO_RAW(UPPER(REPLACE(pv_backup_code, '-', '')))
           ,DBMS_CRYPTO.HASH_SH256));
        
        SELECT ame.ame_id INTO ln_ame_id
          FROM IDP.AUTH_MFA_ENROLLMENT ame
         WHERE ame.tenant_id = pn_tenant_id
           AND ame.user_id = pv_user_id
           AND ame.enrollment_status = gc_status_verified;
        
        SELECT amb.amb_id INTO ln_amb_id
          FROM IDP.AUTH_MFA_BACKUP_CODES amb
         WHERE amb.amb_ame_id = ln_ame_id
           AND amb.code_hash = lv_code_hash
           AND amb.is_used = 'N';
        
        UPDATE IDP.AUTH_MFA_BACKUP_CODES
           SET is_used = 'Y', used_date = SYSTIMESTAMP, used_ip = pv_client_ip
         WHERE amb_id = ln_amb_id;
        
        UPDATE IDP.AUTH_MFA_ENROLLMENT
           SET last_used_date = SYSTIMESTAMP, use_count = use_count + 1
         WHERE ame_id = ln_ame_id;
        
        log_challenge(pn_tenant_id, pv_user_id, gc_challenge_backup, TRUE, NULL, pv_client_ip);
        
         -- Bridge backup code usage to DMS SOC2
         DECLARE
             ln_remaining NUMBER;
         BEGIN
             SELECT COUNT(*) INTO ln_remaining
               FROM IDP.AUTH_MFA_BACKUP_CODES
              WHERE amb_ame_id = ln_ame_id AND is_used = 'N';
             
             IDP.idp_dms_bridge_pkg.bridge_mfa_challenge(
                 pn_tenant_id        => pn_tenant_id
                ,pv_user_id          => pv_user_id
                ,pv_challenge_type   => 'BACKUP_CODE'
                ,pb_was_successful   => TRUE
                ,pv_ip_address       => pv_client_ip
             );
             
             -- Alert if last or no backup codes remaining
             IF ln_remaining <= 1 THEN
                 IDP.idp_dms_bridge_pkg.bridge_security_incident(
                     pn_tenant_id        => pn_tenant_id
                    ,pv_title            => 'MFA Backup Codes Nearly Exhausted'
                    ,pv_incident_type    => 'MFA_BACKUP_LOW'
                    ,pv_severity         => CASE WHEN ln_remaining = 0 THEN 'HIGH' ELSE 'MEDIUM' END
                    ,pc_description      => 'User ' || pv_user_id || 
                                            ' has ' || ln_remaining || ' MFA backup code(s) remaining.'
                    ,pv_username         => pv_user_id
                    ,pv_ip_address       => pv_client_ip
                 );
             END IF;
         EXCEPTION
             WHEN OTHERS THEN NULL;
         END;
        
        COMMIT;
        RETURN TRUE;
    EXCEPTION
        WHEN NO_DATA_FOUND THEN
            log_challenge(pn_tenant_id, pv_user_id, gc_challenge_backup, FALSE, 'INVALID_CODE', pv_client_ip);
            RETURN FALSE;
    END verify_backup_code;
    
    -- ========================================================================
    -- regenerate_backup_codes
    -- ========================================================================
    FUNCTION regenerate_backup_codes
        (pn_tenant_id       IN  NUMBER
        ,pv_user_id         IN  VARCHAR2
        ,pt_backup_codes    OUT t_backup_code_list
        )
    RETURN BOOLEAN IS
        ln_ame_id   NUMBER;
    BEGIN
        SELECT ame.ame_id INTO ln_ame_id
          FROM IDP.AUTH_MFA_ENROLLMENT ame
         WHERE ame.tenant_id = pn_tenant_id
           AND ame.user_id = pv_user_id
           AND ame.enrollment_status = gc_status_verified;
        
        DELETE FROM IDP.AUTH_MFA_BACKUP_CODES WHERE amb_ame_id = ln_ame_id;
        
        FOR ln_i IN 1..10 LOOP
            pt_backup_codes(ln_i) := SUBSTR(RAWTOHEX(DBMS_CRYPTO.RANDOMBYTES(4)), 1, 4) || '-' ||
                                     SUBSTR(RAWTOHEX(DBMS_CRYPTO.RANDOMBYTES(4)), 1, 4);
            INSERT INTO IDP.AUTH_MFA_BACKUP_CODES (amb_ame_id, code_hash)
            VALUES (ln_ame_id, RAWTOHEX(DBMS_CRYPTO.HASH(
                UTL_RAW.CAST_TO_RAW(REPLACE(pt_backup_codes(ln_i), '-', '')), DBMS_CRYPTO.HASH_SH256)));
        END LOOP;
        
        COMMIT;
        RETURN TRUE;
    EXCEPTION
        WHEN NO_DATA_FOUND THEN
            RETURN FALSE;
    END regenerate_backup_codes;
    
    -- ========================================================================
    -- get_backup_code_count
    -- ========================================================================
    FUNCTION get_backup_code_count
        (pn_tenant_id       IN  NUMBER
        ,pv_user_id         IN  VARCHAR2
        )
    RETURN NUMBER IS
        ln_count    NUMBER := 0;
    BEGIN
        SELECT COUNT(*) INTO ln_count
          FROM IDP.AUTH_MFA_BACKUP_CODES amb
              ,IDP.AUTH_MFA_ENROLLMENT ame
         WHERE ame.tenant_id = pn_tenant_id
           AND ame.user_id = pv_user_id
           AND amb.amb_ame_id = ame.ame_id
           AND amb.is_used = 'N';
        RETURN ln_count;
    EXCEPTION
        WHEN NO_DATA_FOUND THEN
            RETURN 0;
    END get_backup_code_count;
    
    -- ========================================================================
    -- trust_device
    -- ========================================================================
    FUNCTION trust_device
        (pn_tenant_id       IN  NUMBER
        ,pv_user_id         IN  VARCHAR2
        ,pv_device_name     IN  VARCHAR2 DEFAULT NULL
        ,pv_user_agent      IN  VARCHAR2 DEFAULT NULL
        ,pv_client_ip       IN  VARCHAR2 DEFAULT NULL
        ,pv_device_token    OUT VARCHAR2
        )
    RETURN BOOLEAN IS
        lt_config   IDP.AUTH_MFA_CONFIG%ROWTYPE;
    BEGIN
        lt_config := get_tenant_config(pn_tenant_id);
        IF lt_config.remember_device_enabled != 'Y' THEN
            RETURN FALSE;
        END IF;
        
        pv_device_token := RAWTOHEX(DBMS_CRYPTO.RANDOMBYTES(32));
        
        INSERT INTO IDP.AUTH_MFA_TRUSTED_DEVICES
            (tenant_id, user_id, device_token, device_name, user_agent, ip_address
            ,trusted_until, device_fingerprint)
        VALUES
            (pn_tenant_id, pv_user_id, pv_device_token, pv_device_name, pv_user_agent, pv_client_ip
            ,SYSTIMESTAMP + NUMTODSINTERVAL(lt_config.remember_device_days, 'DAY')
            ,RAWTOHEX(DBMS_CRYPTO.HASH(UTL_RAW.CAST_TO_RAW(pv_user_agent || pv_client_ip), DBMS_CRYPTO.HASH_SH256)));
        COMMIT;
        RETURN TRUE;
    EXCEPTION
        WHEN OTHERS THEN
            ROLLBACK;
            RETURN FALSE;
    END trust_device;
    
    -- ========================================================================
    -- is_device_trusted
    -- ========================================================================
    FUNCTION is_device_trusted
        (pn_tenant_id       IN  NUMBER
        ,pv_user_id         IN  VARCHAR2
        ,pv_device_token    IN  VARCHAR2
        )
    RETURN BOOLEAN IS
        ln_count    NUMBER := 0;
    BEGIN
        SELECT COUNT(*) INTO ln_count
          FROM IDP.AUTH_MFA_TRUSTED_DEVICES amt
         WHERE amt.tenant_id = pn_tenant_id
           AND amt.user_id = pv_user_id
           AND amt.device_token = pv_device_token
           AND amt.is_active = 'Y'
           AND amt.trusted_until > SYSTIMESTAMP;
        
        IF ln_count > 0 THEN
            UPDATE IDP.AUTH_MFA_TRUSTED_DEVICES
               SET last_used_date = SYSTIMESTAMP, use_count = use_count + 1
             WHERE tenant_id = pn_tenant_id AND user_id = pv_user_id AND device_token = pv_device_token;
            COMMIT;
        END IF;
        RETURN ln_count > 0;
    END is_device_trusted;
    
    -- ========================================================================
    -- revoke_device
    -- ========================================================================
    PROCEDURE revoke_device
        (pn_tenant_id       IN  NUMBER
        ,pv_user_id         IN  VARCHAR2
        ,pn_amt_id          IN  NUMBER
        )
    IS
    BEGIN
        UPDATE IDP.AUTH_MFA_TRUSTED_DEVICES
           SET is_active = 'N', revoked_date = SYSTIMESTAMP, revoked_by = USER
         WHERE amt_id = pn_amt_id AND tenant_id = pn_tenant_id AND user_id = pv_user_id;
        COMMIT;
    END revoke_device;
    
    -- ========================================================================
    -- revoke_all_devices
    -- ========================================================================
    PROCEDURE revoke_all_devices
        (pn_tenant_id       IN  NUMBER
        ,pv_user_id         IN  VARCHAR2
        )
    IS
    BEGIN
        UPDATE IDP.AUTH_MFA_TRUSTED_DEVICES
           SET is_active = 'N', revoked_date = SYSTIMESTAMP, revoked_by = USER
         WHERE tenant_id = pn_tenant_id AND user_id = pv_user_id AND is_active = 'Y';
        COMMIT;
    END revoke_all_devices;
    
    -- ========================================================================
    -- get_trusted_devices
    -- ========================================================================
    FUNCTION get_trusted_devices
        (pn_tenant_id       IN  NUMBER
        ,pv_user_id         IN  VARCHAR2
        ,pc_devices         OUT SYS_REFCURSOR
        )
    RETURN NUMBER IS
        ln_count    NUMBER := 0;
    BEGIN
        SELECT COUNT(*) INTO ln_count
          FROM IDP.AUTH_MFA_TRUSTED_DEVICES amt
         WHERE amt.tenant_id = pn_tenant_id AND amt.user_id = pv_user_id
           AND amt.is_active = 'Y' AND amt.trusted_until > SYSTIMESTAMP;
        
        OPEN pc_devices FOR
            SELECT amt.amt_id, amt.device_name, amt.user_agent, amt.ip_address
                  ,amt.created_date, amt.last_used_date, amt.trusted_until
              FROM IDP.AUTH_MFA_TRUSTED_DEVICES amt
             WHERE amt.tenant_id = pn_tenant_id AND amt.user_id = pv_user_id
               AND amt.is_active = 'Y' AND amt.trusted_until > SYSTIMESTAMP
             ORDER BY amt.last_used_date DESC NULLS LAST;
        RETURN ln_count;
    END get_trusted_devices;
    
    -- ========================================================================
    -- is_mfa_required
    -- ========================================================================
    FUNCTION is_mfa_required
        (pn_tenant_id       IN  NUMBER
        ,pv_user_id         IN  VARCHAR2
        ,pv_user_roles      IN  VARCHAR2 DEFAULT NULL
        )
    RETURN BOOLEAN IS
        lt_config   IDP.AUTH_MFA_CONFIG%ROWTYPE;
    BEGIN
        lt_config := get_tenant_config(pn_tenant_id);
        
        IF lt_config.mfa_required = 'Y' THEN
            RETURN TRUE;
        END IF;
        
        IF lt_config.mfa_required_roles IS NOT NULL AND pv_user_roles IS NOT NULL THEN
            FOR ln_i IN 1..REGEXP_COUNT(lt_config.mfa_required_roles, '[^,]+') LOOP
                IF INSTR(',' || UPPER(pv_user_roles) || ','
                        ,',' || UPPER(TRIM(REGEXP_SUBSTR(lt_config.mfa_required_roles, '[^,]+', 1, ln_i))) || ',') > 0 THEN
                    RETURN TRUE;
                END IF;
            END LOOP;
        END IF;
        RETURN FALSE;
    EXCEPTION
        WHEN NO_DATA_FOUND THEN
            RETURN FALSE;
    END is_mfa_required;
    
    -- ========================================================================
    -- get_mfa_status
    -- ========================================================================
    FUNCTION get_mfa_status
        (pn_tenant_id       IN  NUMBER
        ,pv_user_id         IN  VARCHAR2
        )
    RETURN t_mfa_status IS
        lt_status   t_mfa_status;
        lt_config   IDP.AUTH_MFA_CONFIG%ROWTYPE;
        ld_enrolled TIMESTAMP;
    BEGIN
        lt_config := get_tenant_config(pn_tenant_id);
        lt_status.is_required := is_mfa_required(pn_tenant_id, pv_user_id);
        
        BEGIN
            SELECT ame.enrollment_status, ame.enrolled_date, ame.last_used_date, ame.use_count
              INTO lt_status.enrollment_status, ld_enrolled, lt_status.last_used_date, lt_status.use_count
              FROM IDP.AUTH_MFA_ENROLLMENT ame
             WHERE ame.tenant_id = pn_tenant_id AND ame.user_id = pv_user_id;
            
            lt_status.is_enrolled := (lt_status.enrollment_status = gc_status_verified);
            lt_status.enrolled_date := ld_enrolled;
            lt_status.backup_codes_left := get_backup_code_count(pn_tenant_id, pv_user_id);
            
            SELECT COUNT(*) INTO lt_status.trusted_devices
              FROM IDP.AUTH_MFA_TRUSTED_DEVICES amt
             WHERE amt.tenant_id = pn_tenant_id AND amt.user_id = pv_user_id
               AND amt.is_active = 'Y' AND amt.trusted_until > SYSTIMESTAMP;
            
            IF lt_status.is_required AND NOT lt_status.is_enrolled AND lt_config.mfa_grace_period_days > 0 THEN
                lt_status.in_grace_period := TRUE;
                lt_status.grace_days_left := GREATEST(0, lt_config.mfa_grace_period_days 
                    - EXTRACT(DAY FROM (SYSTIMESTAMP - ld_enrolled)));
            ELSE
                lt_status.in_grace_period := FALSE;
                lt_status.grace_days_left := 0;
            END IF;
        EXCEPTION
            WHEN NO_DATA_FOUND THEN
                lt_status.is_enrolled := FALSE;
                lt_status.enrollment_status := NULL;
                lt_status.backup_codes_left := 0;
                lt_status.trusted_devices := 0;
                lt_status.in_grace_period := FALSE;
                lt_status.grace_days_left := 0;
        END;
        RETURN lt_status;
    END get_mfa_status;
    
    -- ========================================================================
    -- disable_mfa
    -- ========================================================================
    PROCEDURE disable_mfa
        (pn_tenant_id       IN  NUMBER
        ,pv_user_id         IN  VARCHAR2
        ,pv_disabled_by     IN  VARCHAR2
        ,pv_reason          IN  VARCHAR2 DEFAULT NULL
        )
    IS
    BEGIN
        UPDATE IDP.AUTH_MFA_ENROLLMENT
           SET enrollment_status = gc_status_disabled
              ,disabled_date = SYSTIMESTAMP, disabled_by = pv_disabled_by, disabled_reason = pv_reason
         WHERE tenant_id = pn_tenant_id AND user_id = pv_user_id;
        
        UPDATE IDP.AUTH_MFA_TRUSTED_DEVICES
           SET is_active = 'N', revoked_date = SYSTIMESTAMP, revoked_by = pv_disabled_by
         WHERE tenant_id = pn_tenant_id AND user_id = pv_user_id AND is_active = 'Y';
         
        -- Bridge enrollment completion to DMS SOC2
        BEGIN
           IDP.idp_dms_bridge_pkg.bridge_mfa_enrollment(
               pn_tenant_id        => pn_tenant_id
              ,pv_user_id          => pv_user_id
              ,pv_action           => 'COMPLETED'
              ,pv_ip_address       => NULL  -- Not available in this function
           );
        EXCEPTION
           WHEN OTHERS THEN NULL;
        END;
         
        COMMIT;
    END disable_mfa;
    
    -- ========================================================================
    -- enable_mfa
    -- ========================================================================
    PROCEDURE enable_mfa
        (pn_tenant_id       IN  NUMBER
        ,pv_user_id         IN  VARCHAR2
        )
    IS
    BEGIN
        UPDATE IDP.AUTH_MFA_ENROLLMENT
           SET enrollment_status = gc_status_verified
              ,disabled_date = NULL, disabled_by = NULL, disabled_reason = NULL, modified_date = SYSTIMESTAMP
         WHERE tenant_id = pn_tenant_id AND user_id = pv_user_id AND enrollment_status = gc_status_disabled;
        COMMIT;
    END enable_mfa;
    
    -- ========================================================================
    -- reset_mfa
    -- ========================================================================
    PROCEDURE reset_mfa
        (pn_tenant_id       IN  NUMBER
        ,pv_user_id         IN  VARCHAR2
        ,pv_reset_by        IN  VARCHAR2
        )
    IS
        ln_ame_id   NUMBER;
    BEGIN
        BEGIN
            SELECT ame.ame_id INTO ln_ame_id
              FROM IDP.AUTH_MFA_ENROLLMENT ame
             WHERE ame.tenant_id = pn_tenant_id AND ame.user_id = pv_user_id;
            
            DELETE FROM IDP.AUTH_MFA_BACKUP_CODES WHERE amb_ame_id = ln_ame_id;
            DELETE FROM IDP.AUTH_MFA_ENROLLMENT WHERE ame_id = ln_ame_id;
        EXCEPTION
            WHEN NO_DATA_FOUND THEN NULL;
        END;
        
        UPDATE IDP.AUTH_MFA_TRUSTED_DEVICES
           SET is_active = 'N', revoked_date = SYSTIMESTAMP, revoked_by = pv_reset_by
         WHERE tenant_id = pn_tenant_id AND user_id = pv_user_id AND is_active = 'Y';
         
        -- Bridge MFA reset to DMS SOC2
        BEGIN
           IDP.idp_dms_bridge_pkg.bridge_mfa_enrollment(
               pn_tenant_id        => pn_tenant_id
              ,pv_user_id          => pv_user_id
              ,pv_action           => 'RESET'
           );
           
           -- Create security incident for MFA reset (audit trail)
           IDP.idp_dms_bridge_pkg.bridge_security_incident(
               pn_tenant_id        => pn_tenant_id
              ,pv_title            => 'MFA Reset for User'
              ,pv_incident_type    => 'MFA_RESET'
              ,pv_severity         => 'LOW'
              ,pc_description      => 'MFA was reset for user ' || pv_user_id || 
                                      ' by ' || pv_reset_by || '. User must re-enroll.'
              ,pv_username         => pv_user_id
           );
        EXCEPTION
           WHEN OTHERS THEN NULL;
        END;
         
        COMMIT;
    END reset_mfa;
    
    -- ========================================================================
    -- get_challenge_history
    -- ========================================================================
    FUNCTION get_challenge_history
        (pn_tenant_id       IN  NUMBER
        ,pv_user_id         IN  VARCHAR2
        ,pn_days_back       IN  NUMBER DEFAULT 30
        ,pc_history         OUT SYS_REFCURSOR
        )
    RETURN NUMBER IS
        ln_count    NUMBER := 0;
    BEGIN
        SELECT COUNT(*) INTO ln_count
          FROM IDP.AUTH_MFA_CHALLENGES amh
         WHERE amh.tenant_id = pn_tenant_id AND amh.user_id = pv_user_id
           AND amh.challenge_timestamp > SYSTIMESTAMP - NUMTODSINTERVAL(pn_days_back, 'DAY');
        
        OPEN pc_history FOR
            SELECT amh.amh_id, amh.challenge_type, amh.challenge_timestamp
                  ,amh.was_successful, amh.failure_reason, amh.ip_address
              FROM IDP.AUTH_MFA_CHALLENGES amh
             WHERE amh.tenant_id = pn_tenant_id AND amh.user_id = pv_user_id
               AND amh.challenge_timestamp > SYSTIMESTAMP - NUMTODSINTERVAL(pn_days_back, 'DAY')
             ORDER BY amh.challenge_timestamp DESC;
        RETURN ln_count;
    END get_challenge_history;

END mfa_auth_pkg;
/


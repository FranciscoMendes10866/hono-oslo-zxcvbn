DROP TRIGGER IF EXISTS update_users_timestamp;

DROP INDEX IF EXISTS idx_user_sessions_user_id;

DROP INDEX IF EXISTS idx_users_email;

DROP TABLE IF EXISTS user_sessions;

DROP TABLE IF EXISTS email_verification_requests;

DROP TABLE IF EXISTS password_update_requests;

DROP TABLE IF EXISTS email_update_requests;

DROP TABLE IF EXISTS password_reset_requests;

DROP TABLE IF EXISTS users;

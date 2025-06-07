CREATE TABLE users (
    id TEXT PRIMARY KEY DEFAULT (uuid7 ()),
    username TEXT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    email_verified BOOLEAN DEFAULT FALSE,
    created_at INTEGER NOT NULL DEFAULT (CAST(strftime ('%s', 'now') AS INTEGER) * 1000)
);

CREATE TABLE password_reset_requests (
    user_id TEXT PRIMARY KEY,
    code_challenge TEXT NOT NULL,
    code_challenge_method TEXT DEFAULT 'S256',
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (CAST(strftime ('%s', 'now') AS INTEGER) * 1000),
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE TABLE email_update_requests (
    user_id TEXT PRIMARY KEY,
    new_email TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    code_challenge_method TEXT DEFAULT 'S256',
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (CAST(strftime ('%s', 'now') AS INTEGER) * 1000),
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE TABLE password_update_requests (
    user_id TEXT PRIMARY KEY,
    code_challenge TEXT NOT NULL,
    code_challenge_method TEXT DEFAULT 'S256',
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (CAST(strftime ('%s', 'now') AS INTEGER) * 1000),
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE TABLE email_verification_requests (
    user_id TEXT PRIMARY KEY,
    code_challenge TEXT NOT NULL,
    code_challenge_method TEXT DEFAULT 'S256',
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (CAST(strftime ('%s', 'now') AS INTEGER) * 1000),
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE TABLE user_sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (CAST(strftime ('%s', 'now') AS INTEGER) * 1000),
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE INDEX idx_users_email ON users (email);

CREATE INDEX idx_user_sessions_user_id ON user_sessions (user_id);

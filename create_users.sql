-- Create users table in logviewer database
-- Run after creating database: psql -U postgres -d logviewer -f create_users.sql
-- Or the backend will create this table automatically on startup (init_db).

CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

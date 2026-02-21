-- schema.sql
-- Warning: This will wipe all data in the users and magic_links tables.

DROP TABLE IF EXISTS magic_links;
DROP TABLE IF EXISTS users;

CREATE TABLE users (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email       TEXT UNIQUE NOT NULL,
    created_at  TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE magic_links (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID REFERENCES users(id) ON DELETE CASCADE,
    token       TEXT UNIQUE NOT NULL,
    expires_at  TIMESTAMP WITH TIME ZONE NOT NULL,
    used_at     TIMESTAMP WITH TIME ZONE
);

-- Seed data for testing
INSERT INTO users (email) VALUES ('matan@lurey.org');

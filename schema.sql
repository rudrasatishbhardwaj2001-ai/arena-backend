CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE TABLE users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  google_sub TEXT UNIQUE NOT NULL, email TEXT UNIQUE NOT NULL, name TEXT, photo_url TEXT, phone TEXT,
  role TEXT NOT NULL DEFAULT 'player' CHECK (role IN ('player','creator','admin')),
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended')),
  creator_granted_at TIMESTAMPTZ, creator_granted_via UUID,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE TABLE free_fire_profiles (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID UNIQUE NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  uid TEXT NOT NULL, nickname TEXT NOT NULL, region TEXT, updated_at TIMESTAMPTZ DEFAULT now());
CREATE TABLE creator_access_codes (
  code_id UUID PRIMARY KEY DEFAULT gen_random_uuid(), code_hash TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled')),
  created_by UUID REFERENCES users(id), created_at TIMESTAMPTZ DEFAULT now(),
  expires_at TIMESTAMPTZ, max_uses INT NOT NULL DEFAULT 1, used_count INT NOT NULL DEFAULT 0,
  CHECK (used_count <= max_uses));
CREATE TABLE platform_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
INSERT INTO platform_settings VALUES ('creator_fee_paise','9900');
CREATE TABLE tournaments (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_id UUID NOT NULL REFERENCES users(id),
  name TEXT NOT NULL, description TEXT, game TEXT NOT NULL DEFAULT 'free_fire',
  mode TEXT NOT NULL CHECK (mode IN ('BR','CS')),  -- extend CHECK for future modes
  starts_at TIMESTAMPTZ NOT NULL, reg_start TIMESTAMPTZ NOT NULL, reg_end TIMESTAMPTZ NOT NULL,
  min_players INT NOT NULL CHECK (min_players > 0), max_players INT NOT NULL,
  entry_fee_paise INT NOT NULL DEFAULT 0 CHECK (entry_fee_paise >= 0),
  prize_pool TEXT, rules TEXT, banner_url TEXT, room_id TEXT, room_password TEXT, map TEXT,
  status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN
    ('draft','upcoming','registration_open','full','live','completed','cancelled')),
  creator_fee_paid BOOLEAN NOT NULL DEFAULT false,
  published_at TIMESTAMPTZ, created_at TIMESTAMPTZ DEFAULT now(),
  CHECK (max_players >= min_players), CHECK (reg_end > reg_start));
CREATE INDEX ON tournaments (status, published_at DESC);
CREATE TABLE tournament_registrations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tournament_id UUID NOT NULL REFERENCES tournaments(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users(id),
  ff_uid TEXT NOT NULL, ff_nickname TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN
    ('pending','payment_pending','confirmed','payment_failed','cancelled')),
  verification_status TEXT NOT NULL DEFAULT 'pending' CHECK (verification_status IN ('pending','verified','rejected')),
  created_at TIMESTAMPTZ DEFAULT now(),
  UNIQUE (tournament_id, user_id));
CREATE UNIQUE INDEX one_uid_per_tournament ON tournament_registrations (tournament_id, ff_uid)
  WHERE status IN ('payment_pending','confirmed');
CREATE TABLE payments (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  kind TEXT NOT NULL CHECK (kind IN ('entry','creator_fee')),
  user_id UUID NOT NULL REFERENCES users(id),
  tournament_id UUID NOT NULL REFERENCES tournaments(id),
  registration_id UUID REFERENCES tournament_registrations(id),
  amount_paise INT NOT NULL, razorpay_order_id TEXT UNIQUE NOT NULL, razorpay_payment_id TEXT UNIQUE,
  status TEXT NOT NULL DEFAULT 'created' CHECK (status IN ('created','paid','failed')),
  created_at TIMESTAMPTZ DEFAULT now(), paid_at TIMESTAMPTZ);
CREATE TABLE notifications (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(), user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  title TEXT NOT NULL, body TEXT, read BOOLEAN DEFAULT false, created_at TIMESTAMPTZ DEFAULT now());
CREATE TABLE tournament_results (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tournament_id UUID NOT NULL REFERENCES tournaments(id) ON DELETE CASCADE,
  rank INT NOT NULL, name TEXT NOT NULL, ff_uid TEXT, kills INT, score INT, prize TEXT, remarks TEXT);
CREATE TABLE audit_logs (
  id BIGSERIAL PRIMARY KEY, actor_id UUID REFERENCES users(id), action TEXT NOT NULL,
  entity TEXT, entity_id TEXT, meta JSONB, created_at TIMESTAMPTZ DEFAULT now());

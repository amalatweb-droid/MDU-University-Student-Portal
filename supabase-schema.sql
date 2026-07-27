-- Run once in Supabase: SQL Editor -> New query -> Run.
create table if not exists public.mdu_users (
  email text primary key check (email ~* '^[^[:space:]@]+@mdu\\.edu$'),
  name text not null,
  role text not null check (role in ('student','lecturer','admin')),
  department text not null,
  active boolean not null default true,
  totp_secret text not null,
  password_hash text not null,
  created_at timestamptz not null default now()
);
create table if not exists public.mdu_sessions (
  id text primary key,
  email text not null references public.mdu_users(email) on delete cascade,
  verified boolean not null default false,
  csrf text not null,
  expires_at timestamptz not null
);
create table if not exists public.mdu_audit_logs (
  id bigint generated always as identity primary key,
  created_at timestamptz not null default now(),
  type text not null,
  email text,
  detail text not null default ''
);
alter table public.mdu_users enable row level security;
alter table public.mdu_sessions enable row level security;
alter table public.mdu_audit_logs enable row level security;

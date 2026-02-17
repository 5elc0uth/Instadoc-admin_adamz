-- Instadoc Admin Dashboard schema additions (recommended)
-- This file focuses on: unified activity feed, admin audit trail, doctor/patient assignments, and soft delete.

-- 1) Soft delete support (profiles)
-- If profiles table already exists, add deleted_at:
alter table if exists public.profiles
  add column if not exists deleted_at timestamptz null;

-- Optional: ensure status column exists
alter table if exists public.profiles
  add column if not exists status text default 'active';

-- 2) Admin audit log (private, detailed)
create table if not exists public.admin_audit_log (
  id uuid default gen_random_uuid() primary key,
  admin_id uuid not null references public.profiles(id),
  target_user_id uuid null references public.profiles(id),
  module text not null check (module in ('users','tickets','doctors')),
  action text not null,
  reason text not null,
  created_at timestamptz default now()
);

-- 3) Platform activity feed (public-facing within admin UI)
create table if not exists public.platform_activity (
  id uuid default gen_random_uuid() primary key,
  actor_id uuid not null references public.profiles(id),
  target_user_id uuid null references public.profiles(id),
  module text not null check (module in ('users','tickets','doctors')),
  action text not null,
  description text not null,
  created_at timestamptz default now()
);

create index if not exists idx_platform_activity_created_at on public.platform_activity(created_at desc);

-- 4) Doctor ↔ Patient assignments
create table if not exists public.doctor_patient_assignments (
  id uuid default gen_random_uuid() primary key,
  doctor_id uuid not null references public.profiles(id),
  patient_id uuid not null references public.profiles(id),
  assigned_by uuid not null references public.profiles(id),
  assigned_at timestamptz default now(),
  unique (doctor_id, patient_id)
);

create index if not exists idx_assignments_doctor on public.doctor_patient_assignments(doctor_id);
create index if not exists idx_assignments_patient on public.doctor_patient_assignments(patient_id);

-- =========================
-- RLS (Row Level Security) - TEMPLATE
-- You must tailor these to your environment.
-- The admin dashboard uses an ANON key, so RLS must enforce "admin only" writes.
-- =========================

-- Enable RLS
alter table public.admin_audit_log enable row level security;
alter table public.platform_activity enable row level security;
alter table public.doctor_patient_assignments enable row level security;

-- Helper: "current user is admin" check (requires profiles table and auth.uid() mapping)
-- Policy for admin-only access:
-- NOTE: you may already have a similar policy; adjust as needed.

-- admin_audit_log: admins can read/insert, nobody else
drop policy if exists admin_audit_log_admin_only on public.admin_audit_log;
create policy admin_audit_log_admin_only on public.admin_audit_log
for all
using (exists (select 1 from public.profiles p where p.id = auth.uid() and p.role = 'admin' and p.deleted_at is null))
with check (exists (select 1 from public.profiles p where p.id = auth.uid() and p.role = 'admin' and p.deleted_at is null));

-- platform_activity: admins can read/insert
drop policy if exists platform_activity_admin_only on public.platform_activity;
create policy platform_activity_admin_only on public.platform_activity
for all
using (exists (select 1 from public.profiles p where p.id = auth.uid() and p.role = 'admin' and p.deleted_at is null))
with check (exists (select 1 from public.profiles p where p.id = auth.uid() and p.role = 'admin' and p.deleted_at is null));

-- doctor_patient_assignments: admins can read/insert/delete
drop policy if exists assignments_admin_only on public.doctor_patient_assignments;
create policy assignments_admin_only on public.doctor_patient_assignments
for all
using (exists (select 1 from public.profiles p where p.id = auth.uid() and p.role = 'admin' and p.deleted_at is null))
with check (exists (select 1 from public.profiles p where p.id = auth.uid() and p.role = 'admin' and p.deleted_at is null));

-- IMPORTANT: If you also want doctors to read their own assigned patients, add a separate SELECT policy for doctors.


-- =========================
-- 5) SUPABASE AUTH → PROFILES + ACTIVITY (Signup logging)
--
-- If users register via Supabase Auth (auth.users), that does NOT automatically create rows in your custom tables.
-- This section adds:
--   - A SECURITY DEFINER trigger that (a) creates/updates a matching row in public.profiles, then
--     (b) writes a "USER_REGISTERED" entry into public.platform_activity.
--
-- Notes:
--  - Runs as the function owner (typically postgres when created via SQL Editor), so it can bypass RLS.
--  - Uses dynamic SQL so it won't break if your profiles table uses different column names.
--  - Make sure your profiles table has a primary key id uuid that matches auth.users.id.
-- =========================

create or replace function public.handle_new_auth_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  has_email boolean;
  has_full_name boolean;
  has_name boolean;
  has_role boolean;
  has_status boolean;
  meta_role text;
  meta_full_name text;
begin
  -- Ensure profile exists (minimum viable insert)
  execute format('insert into public.profiles (id) values (%L) on conflict (id) do nothing', new.id);

  -- Detect optional columns on profiles
  select exists (
    select 1 from information_schema.columns
    where table_schema = 'public' and table_name = 'profiles' and column_name = 'email'
  ) into has_email;

  select exists (
    select 1 from information_schema.columns
    where table_schema = 'public' and table_name = 'profiles' and column_name = 'full_name'
  ) into has_full_name;

  select exists (
    select 1 from information_schema.columns
    where table_schema = 'public' and table_name = 'profiles' and column_name = 'name'
  ) into has_name;

  select exists (
    select 1 from information_schema.columns
    where table_schema = 'public' and table_name = 'profiles' and column_name = 'role'
  ) into has_role;

  select exists (
    select 1 from information_schema.columns
    where table_schema = 'public' and table_name = 'profiles' and column_name = 'status'
  ) into has_status;

  -- Pull metadata if present
  meta_role := coalesce(new.raw_user_meta_data->>'role', null);
  meta_full_name := coalesce(new.raw_user_meta_data->>'full_name', new.raw_user_meta_data->>'name', null);

  -- Update the profile with whatever columns are available
  if has_email then
    execute format('update public.profiles set email = %L where id = %L', new.email, new.id);
  end if;

  if has_full_name and meta_full_name is not null then
    execute format('update public.profiles set full_name = %L where id = %L', meta_full_name, new.id);
  end if;

  if has_name and meta_full_name is not null then
    execute format('update public.profiles set name = %L where id = %L', meta_full_name, new.id);
  end if;

  if has_role and meta_role is not null then
    execute format('update public.profiles set role = %L where id = %L', meta_role, new.id);
  end if;

  if has_status then
    -- Keep your convention: 'active' or 'ACTIVE' — defaulting to 'active'
    execute format('update public.profiles set status = coalesce(status, ''active'') where id = %L', new.id);
  end if;

  -- Log registration in platform_activity (admins can read it; insert bypasses RLS via SECURITY DEFINER)
  insert into public.platform_activity (
    actor_id,
    target_user_id,
    module,
    action,
    description,
    created_at
  ) values (
    new.id,
    new.id,
    'users',
    'USER_REGISTERED',
    coalesce(meta_full_name, new.email) || ' registered via Supabase Auth',
    now()
  );

  return new;
end;
$$;

-- Trigger on auth.users (runs after signup)
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
after insert on auth.users
for each row execute function public.handle_new_auth_user();

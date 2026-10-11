/**
 * A small imitation of what a real Supabase database has before your own
 * migrations run: the API roles, the `auth` schema with `auth.uid()`, the
 * `storage` schema, and the default grants that expose `public` tables.
 *
 * It only needs to be faithful where access control is decided. The function
 * bodies below match Supabase's own definitions of auth.uid(), auth.role()
 * and auth.jwt(), which read the JWT claims PostgREST puts in
 * `request.jwt.claims` for every request.
 */

export interface ShimOptions {
  /**
   * Before Oct 30, 2026 Supabase granted every new `public` table to the
   * `anon` and `authenticated` roles by default. After that date new tables
   * need explicit grants. We default to the old behaviour because it is the
   * worst case for leaks and still true for every table created before then.
   */
  defaultGrants: boolean;
}

export function supabaseShimSql(options: ShimOptions): string {
  const defaultGrants = options.defaultGrants
    ? `
alter default privileges in schema public grant all on tables to anon, authenticated, service_role;
alter default privileges in schema public grant all on sequences to anon, authenticated, service_role;
alter default privileges in schema public grant all on functions to anon, authenticated, service_role;`
    : "";

  return `
-- Roles the Supabase API switches into for each request.
create role anon nologin noinherit;
create role authenticated nologin noinherit;
create role service_role nologin noinherit bypassrls;
create role authenticator noinherit;
grant anon, authenticated, service_role to authenticator;

-- Roles that real migrations sometimes mention (owners, grants).
create role supabase_admin nologin bypassrls;
create role supabase_auth_admin nologin;
create role supabase_storage_admin nologin;
create role supabase_realtime_admin nologin;
create role dashboard_user nologin;
create role pgbouncer nologin;

create schema extensions;
create schema auth;
create schema storage;
create schema realtime;
create schema graphql_public;

grant usage on schema public, extensions, auth, storage, graphql_public
  to anon, authenticated, service_role;

create table auth.users (
  instance_id uuid,
  id uuid primary key,
  aud varchar(255),
  role varchar(255),
  email varchar(255),
  encrypted_password varchar(255),
  email_confirmed_at timestamptz,
  invited_at timestamptz,
  confirmation_token varchar(255),
  confirmation_sent_at timestamptz,
  recovery_token varchar(255),
  recovery_sent_at timestamptz,
  email_change_token_new varchar(255),
  email_change varchar(255),
  email_change_sent_at timestamptz,
  last_sign_in_at timestamptz,
  raw_app_meta_data jsonb default '{}'::jsonb,
  raw_user_meta_data jsonb default '{}'::jsonb,
  is_super_admin boolean,
  created_at timestamptz default now(),
  updated_at timestamptz default now(),
  phone text unique,
  phone_confirmed_at timestamptz,
  confirmed_at timestamptz,
  banned_until timestamptz,
  is_sso_user boolean not null default false,
  deleted_at timestamptz,
  is_anonymous boolean not null default false
);

create function auth.uid() returns uuid language sql stable as $$
  select nullif(coalesce(
    current_setting('request.jwt.claim.sub', true),
    (nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'sub')
  ), '')::uuid
$$;

create function auth.role() returns text language sql stable as $$
  select nullif(coalesce(
    current_setting('request.jwt.claim.role', true),
    (nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'role')
  ), '')::text
$$;

create function auth.email() returns text language sql stable as $$
  select nullif(coalesce(
    current_setting('request.jwt.claim.email', true),
    (nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'email')
  ), '')::text
$$;

create function auth.jwt() returns jsonb language sql stable as $$
  select coalesce(
    nullif(current_setting('request.jwt.claim', true), ''),
    nullif(current_setting('request.jwt.claims', true), '')
  )::jsonb
$$;

grant execute on all functions in schema auth to anon, authenticated, service_role;

-- Storage: buckets and the objects inside them. Supabase protects objects
-- with RLS policies on storage.objects, just like normal tables.
create table storage.buckets (
  id text primary key,
  name text not null unique,
  owner uuid,
  owner_id text,
  public boolean default false,
  avif_autodetection boolean default false,
  file_size_limit bigint,
  allowed_mime_types text[],
  type text,
  created_at timestamptz default now(),
  updated_at timestamptz default now()
);

create table storage.objects (
  id uuid primary key default gen_random_uuid(),
  bucket_id text references storage.buckets(id),
  name text,
  owner uuid,
  owner_id text,
  metadata jsonb,
  user_metadata jsonb,
  version text,
  created_at timestamptz default now(),
  updated_at timestamptz default now(),
  last_accessed_at timestamptz default now()
);

alter table storage.buckets enable row level security;
alter table storage.objects enable row level security;
grant all on storage.buckets, storage.objects to anon, authenticated, service_role;

create function storage.foldername(name text) returns text[] language plpgsql immutable as $$
declare
  _parts text[];
begin
  select string_to_array(name, '/') into _parts;
  return _parts[1:array_length(_parts, 1) - 1];
end
$$;

create function storage.filename(name text) returns text language plpgsql immutable as $$
declare
  _parts text[];
begin
  select string_to_array(name, '/') into _parts;
  return _parts[array_length(_parts, 1)];
end
$$;

create function storage.extension(name text) returns text language plpgsql immutable as $$
declare
  _parts text[];
  _filename text;
begin
  select string_to_array(name, '/') into _parts;
  select _parts[array_length(_parts, 1)] into _filename;
  return reverse(split_part(reverse(_filename), '.', 1));
end
$$;

grant execute on all functions in schema storage to anon, authenticated, service_role;

-- Realtime: migrations often add tables to this publication.
create publication supabase_realtime;
${defaultGrants}
`;
}

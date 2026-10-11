-- A small app in the style Lovable and Bolt generate.
-- It contains the mistakes Vibesecure looks for, next to tables that are done right.

-- profiles: one per user, created by a trigger. Done right.
create table public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  full_name text,
  email text,
  avatar_url text,
  role text not null default 'user' check (role in ('user', 'admin')),
  created_at timestamptz not null default now()
);

alter table public.profiles enable row level security;

create policy "Users can view their own profile"
  on public.profiles for select
  using (auth.uid() = id);

create policy "Users can update their own profile"
  on public.profiles for update
  using (auth.uid() = id);

create function public.handle_new_user()
returns trigger
language plpgsql
security definer set search_path = public
as $$
begin
  insert into public.profiles (id, full_name, email)
  values (new.id, new.raw_user_meta_data ->> 'full_name', new.email);
  return new;
end;
$$;

create trigger on_auth_user_created
  after insert on auth.users
  for each row execute procedure public.handle_new_user();

-- posts: RLS was never turned on, so the public API key can read and change everything.
create table public.posts (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  title text not null,
  body text,
  is_published boolean not null default false,
  created_at timestamptz not null default now()
);

-- notes: RLS is on, but the policy lets everyone in.
create table public.notes (
  id bigint generated always as identity primary key,
  user_id uuid not null references auth.users(id),
  content text not null,
  created_at timestamptz default now()
);

alter table public.notes enable row level security;

create policy "Enable all access"
  on public.notes for all
  using (true)
  with check (true);

-- todos: done right.
create table public.todos (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null default auth.uid() references auth.users(id),
  task text not null,
  done boolean not null default false
);

alter table public.todos enable row level security;

create policy "Users manage their own todos"
  on public.todos for all to authenticated
  using ((select auth.uid()) = user_id)
  with check ((select auth.uid()) = user_id);

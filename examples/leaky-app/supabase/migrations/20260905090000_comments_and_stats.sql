-- comments: signed-in users can read them (fine), but the insert policy
-- doesn't check who the author is.
create table public.comments (
  id uuid primary key default gen_random_uuid(),
  post_id uuid not null references public.posts(id) on delete cascade,
  author_id uuid not null references auth.users(id),
  body text not null check (char_length(body) <= 2000),
  created_at timestamptz default now()
);

alter table public.comments enable row level security;

create policy "Comments are visible to signed-in users"
  on public.comments for select to authenticated
  using (true);

create policy "Signed-in users can comment"
  on public.comments for insert to authenticated
  with check (true);

-- categories: public reference data. Done right.
create table public.categories (
  id serial primary key,
  name text not null unique
);

alter table public.categories enable row level security;

create policy "Categories are public"
  on public.categories for select
  using (true);

-- A stats view. Views skip RLS unless they are created with security_invoker = on.
create view public.author_stats as
  select p.id as user_id, p.full_name, p.email, count(n.id) as note_count
  from public.profiles p
  left join public.notes n on n.user_id = p.id
  group by p.id, p.full_name, p.email;

-- Realtime and a cron job. pg_cron isn't available offline, so the scan skips these lines.
alter publication supabase_realtime add table public.comments;

create extension if not exists pg_cron;

select cron.schedule(
  'nightly-cleanup',
  '0 3 * * *',
  $$delete from public.notes where created_at < now() - interval '90 days'$$
);

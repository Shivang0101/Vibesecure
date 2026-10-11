-- Functions the app calls with supabase.rpc(). Postgres lets everyone call a
-- new function unless EXECUTE is revoked, so each of these is public API.

-- is_admin: the usual helper for admin-only policies. Security definer, so it
-- can read profiles without tripping over RLS. Fine on its own, but users can
-- change their own profiles.role (see the update policy in the first
-- migration), so anyone can make this return true for themselves.
create function public.is_admin()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (select 1 from public.profiles where id = auth.uid() and role = 'admin');
$$;

create policy "Admins can delete any comment"
  on public.comments for delete to authenticated
  using (public.is_admin());

-- delete_user_notes: security definer and never checks who is calling,
-- so anyone can wipe anyone's notes.
create function public.delete_user_notes(target_user uuid)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  delete from public.notes where user_id = target_user;
end;
$$;

-- search_posts: builds its query by pasting in the search text (SQL injection),
-- and runs it with the owner's rights.
create function public.search_posts(term text)
returns setof public.posts
language plpgsql
security definer
as $$
begin
  return query execute
    'select * from public.posts where title ilike ''%' || term || '%''';
end;
$$;

-- post_count: security invoker, so RLS applies. Done right.
create function public.post_count()
returns bigint
language sql
stable
as $$
  select count(*) from public.posts;
$$;

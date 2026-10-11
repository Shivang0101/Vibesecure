-- avatars: a public bucket. Each user uploads into a folder named after their id. Done right.
insert into storage.buckets (id, name, public) values ('avatars', 'avatars', true);

create policy "Avatar images are publicly accessible"
  on storage.objects for select
  using (bucket_id = 'avatars');

create policy "Users can upload their own avatar"
  on storage.objects for insert to authenticated
  with check (bucket_id = 'avatars' and (storage.foldername(name))[1] = auth.uid()::text);

-- invoices: a private bucket, but any signed-in user can read everyone's invoices.
insert into storage.buckets (id, name, public) values ('invoices', 'invoices', false);

create policy "Signed-in users can read invoices"
  on storage.objects for select to authenticated
  using (bucket_id = 'invoices');

create policy "Users upload their own invoices"
  on storage.objects for insert to authenticated
  with check (bucket_id = 'invoices' and (storage.foldername(name))[1] = auth.uid()::text);

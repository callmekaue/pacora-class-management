-- ============================================================
-- GESTOR DE TURMAS — schema SQL (Supabase / PostgreSQL)
--
-- Como usar:
-- 1. Crie um projeto gratuito em https://supabase.com
-- 2. Abra "SQL Editor" no menu lateral do projeto
-- 3. Cole TODO este arquivo e clique em "Run"
-- 4. Em Project Settings -> API, copie a "Project URL" e a chave
--    "anon public" e cole no app, no ícone "Banco de dados"
--    (barra lateral) ou em Relatórios -> Conectar banco de dados.
--
-- Já rodou este script antes? Pode rodar de novo sem medo: todos os
-- comandos usam "if not exists" / "on conflict do nothing", então
-- atualizações (como a tabela class_representatives ou a coluna
-- whatsapp) são adicionadas sem apagar ou duplicar nada que já existe.
--
-- SEGURANÇA (login + RLS):
-- O acesso exige login (Supabase Auth). A tabela "profiles" guarda o nível
-- de cada usuário ('adm' ou 'representante') e se está ativo. O PRIMEIRO
-- usuário criado vira ADM; os demais nascem inativos até o ADM liberar
-- no painel do app. A chave anon NÃO é credencial administrativa; quem
-- protege os dados são o login e as políticas abaixo. Apagar em massa
-- (alunos, notas, diário...) é permitido só ao ADM. Nunca use a chave
-- service_role no front-end.
-- Passo a passo: rode este script, crie o 1º usuário em Authentication ->
-- Users (ou pelo app) e entre com ele. Se já existia um usuário antes de
-- rodar o script, o mais antigo é promovido a ADM automaticamente.
-- ============================================================

create table if not exists classes (
  id text primary key,
  name text not null,
  day_index int not null,
  note text default ''
);

-- se a tabela classes já existia de uma versão anterior deste script
alter table classes add column if not exists note text default '';

create table if not exists groups (
  id text primary key,
  class_id text not null references classes(id),
  name text not null,
  status text not null default 'ativo',
  leader_id text,
  group_grade numeric,
  created_at date
);

create table if not exists students (
  id text primary key,
  name text not null,
  rgm text not null,
  class_id text not null references classes(id),
  group_id text,
  status text not null default 'ativo',
  observations text default '',
  whatsapp text default '',
  created_at date
);

-- se a tabela students já existia de uma versão anterior deste script, garante a coluna nova
alter table students add column if not exists whatsapp text default '';

create table if not exists individual_grades (
  id text primary key,
  student_id text not null,
  class_id text,
  group_id text,
  value numeric not null,
  label text,
  date date,
  kind text default 'aluno'
);

-- notas antigas contam como 'aluno'; 'integrante' = nota individual dentro do grupo
alter table individual_grades add column if not exists kind text default 'aluno';

create table if not exists group_grades_history (
  id text primary key,
  group_id text not null,
  value numeric not null,
  date date
);

create table if not exists diary_entries (
  id text primary key,
  date date not null,
  class_id text,
  group_id text,
  student_id text,
  category text not null,
  description text not null,
  created_at_ms bigint
);

create table if not exists group_history (
  id text primary key,
  group_id text not null,
  class_id text,
  date date,
  description text
);

create table if not exists student_history (
  id text primary key,
  student_id text not null,
  date date,
  from_group_id text,
  to_group_id text,
  description text
);

create table if not exists categories (
  name text primary key
);

create table if not exists app_meta (
  id text primary key default 'singleton',
  is_demo boolean default true
);

create table if not exists class_representatives (
  id text primary key,
  class_id text not null references classes(id),
  student_id text not null,
  created_at date
);

create table if not exists events (
  id text primary key,
  date date not null,
  title text not null,
  description text default '',
  created_at_ms bigint
);

-- índices úteis para os filtros mais comuns
create index if not exists idx_groups_class on groups(class_id);
create index if not exists idx_students_class on students(class_id);
create index if not exists idx_students_group on students(group_id);
create index if not exists idx_individual_grades_student on individual_grades(student_id);
create index if not exists idx_diary_class on diary_entries(class_id);
create index if not exists idx_diary_group on diary_entries(group_id);
create index if not exists idx_group_history_group on group_history(group_id);
create index if not exists idx_student_history_student on student_history(student_id);
create index if not exists idx_class_reps_class on class_representatives(class_id);
create index if not exists idx_events_date on events(date);

-- ============================================================
-- RLS: liberado para a chave anon (sem login), uso individual.
-- ============================================================
alter table classes enable row level security;
alter table groups enable row level security;
alter table students enable row level security;
alter table individual_grades enable row level security;
alter table group_grades_history enable row level security;
alter table diary_entries enable row level security;
alter table group_history enable row level security;
alter table student_history enable row level security;
alter table categories enable row level security;
alter table app_meta enable row level security;
alter table class_representatives enable row level security;
alter table events enable row level security;

create table if not exists profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text,
  name text default '',
  role text not null default 'representante' check (role in ('adm','representante')),
  active boolean not null default false,
  created_at timestamptz default now()
);
alter table profiles enable row level security;

create or replace function public.is_active_user() returns boolean
language sql stable security definer set search_path = public as
$f$ select exists (select 1 from profiles where id = auth.uid() and active) $f$;

create or replace function public.is_adm() returns boolean
language sql stable security definer set search_path = public as
$f$ select exists (select 1 from profiles where id = auth.uid() and active and role = 'adm') $f$;

create table if not exists invites (
  id uuid primary key default gen_random_uuid(),
  email text not null unique,
  name text default '',
  role text not null default 'representante' check (role in ('adm','representante')),
  code text not null,
  created_at timestamptz default now()
);
alter table invites enable row level security;
drop policy if exists "invites_adm" on invites;
create policy "invites_adm" on invites for all to authenticated using (public.is_adm()) with check (public.is_adm());

create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public as
$f$
declare first_user boolean; inv invites%rowtype;
begin
  select not exists (select 1 from profiles) into first_user;
  select * into inv from invites
   where email = lower(new.email) and code = coalesce(new.raw_user_meta_data->>'invite_code','') limit 1;
  if inv.id is not null then
    insert into profiles (id, email, name, role, active) values (new.id, new.email, coalesce(inv.name,''), inv.role, true);
    update auth.users set email_confirmed_at = coalesce(email_confirmed_at, now()) where id = new.id;
    delete from invites where id = inv.id;
  else
    insert into profiles (id, email, name, role, active)
    values (new.id, new.email, coalesce(new.raw_user_meta_data->>'name',''),
            case when first_user then 'adm' else 'representante' end, first_user);
  end if;
  return new;
end
$f$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.handle_new_user();

-- usuário já existente antes deste script: o mais antigo vira ADM
insert into profiles (id, email, role, active)
select id, email, 'adm', true from auth.users
where not exists (select 1 from profiles) order by created_at limit 1;

-- usada pelo painel do ADM: cria/atualiza o perfil e confirma o e-mail do usuário
create or replace function public.admin_upsert_profile(p_id uuid, p_name text, p_role text, p_active boolean) returns void
language plpgsql security definer set search_path = public as
$f$
begin
  if not public.is_adm() then raise exception 'Apenas o administrador pode fazer isso.'; end if;
  if p_role not in ('adm','representante') then raise exception 'Nível inválido.'; end if;
  update auth.users set email_confirmed_at = coalesce(email_confirmed_at, now()) where id = p_id;
  insert into profiles (id, email, name, role, active)
  select id, email, coalesce(p_name,''), p_role, p_active from auth.users where id = p_id
  on conflict (id) do update set name = excluded.name, role = excluded.role, active = excluded.active;
end
$f$;
revoke all on function public.admin_upsert_profile(uuid, text, text, boolean) from public, anon;
grant execute on function public.admin_upsert_profile(uuid, text, text, boolean) to authenticated;

-- observação nas notas
alter table individual_grades add column if not exists observation text default '';
alter table groups add column if not exists group_grade_note text default '';

-- redefinição de senha por link (o ADM gera o link; o usuário escolhe a própria senha)
create table if not exists password_resets (
  email text primary key,
  code text not null,
  expires_at timestamptz not null,
  attempts int not null default 0
);
alter table password_resets enable row level security;
drop policy if exists "resets_adm" on password_resets;
create policy "resets_adm" on password_resets for all to authenticated using (public.is_adm()) with check (public.is_adm());

create or replace function public.admin_create_reset(p_email text, p_code text) returns void
language plpgsql security definer set search_path = public, extensions as
$f$
begin
  if not public.is_adm() then raise exception 'Apenas o administrador pode fazer isso.'; end if;
  if length(coalesce(p_code,'')) < 8 then raise exception 'Código inválido.'; end if;
  if not exists (select 1 from auth.users where lower(email) = lower(p_email)) then raise exception 'Usuário não encontrado.'; end if;
  insert into password_resets (email, code, expires_at, attempts)
  values (lower(p_email), upper(p_code), now() + interval '24 hours', 0)
  on conflict (email) do update set code = excluded.code, expires_at = excluded.expires_at, attempts = 0;
end
$f$;
revoke all on function public.admin_create_reset(text, text) from public, anon;
grant execute on function public.admin_create_reset(text, text) to authenticated;

-- devolve 'ok' ou uma mensagem (não levanta erro, para as tentativas erradas ficarem contadas)
create or replace function public.reset_password_with_code(p_email text, p_code text, p_password text) returns text
language plpgsql security definer set search_path = public, extensions as
$f$
declare r password_resets%rowtype; msg text := 'Link inválido ou expirado. Peça um novo ao administrador.';
begin
  if length(coalesce(p_password,'')) < 6 then return 'A senha precisa ter pelo menos 6 caracteres.'; end if;
  select * into r from password_resets where email = lower(p_email) for update;
  if not found or r.expires_at < now() or r.attempts >= 5 then return msg; end if;
  if r.code <> upper(trim(p_code)) then
    update password_resets set attempts = attempts + 1 where email = r.email;
    return msg;
  end if;
  update auth.users
     set encrypted_password = crypt(p_password, gen_salt('bf', 10)),
         email_confirmed_at = coalesce(email_confirmed_at, now()),
         updated_at = now()
   where lower(email) = lower(p_email);
  delete from password_resets where email = r.email;
  return 'ok';
end
$f$;
grant execute on function public.reset_password_with_code(text, text, text) to anon, authenticated;

-- registro de atividades (somente o ADM lê; ninguém edita ou apaga pelo app)
create table if not exists audit_log (
  id uuid primary key default gen_random_uuid(),
  at timestamptz not null default now(),
  user_id uuid,
  user_email text,
  user_name text,
  action text not null,
  details text default ''
);
create index if not exists idx_audit_at on audit_log (at desc);
alter table audit_log enable row level security;
drop policy if exists "audit_insert" on audit_log;
drop policy if exists "audit_select" on audit_log;
create policy "audit_insert" on audit_log for insert to authenticated with check (public.is_active_user() and user_id = auth.uid());
create policy "audit_select" on audit_log for select to authenticated using (public.is_adm());

drop policy if exists "profiles_select" on profiles;
drop policy if exists "profiles_update" on profiles;
create policy "profiles_select" on profiles for select to authenticated using (id = auth.uid() or public.is_adm());
create policy "profiles_update" on profiles for update to authenticated using (public.is_adm()) with check (public.is_adm());

do $$
declare t text;
begin
  foreach t in array array['classes','groups','students','individual_grades','group_grades_history','diary_entries','group_history','student_history','categories','app_meta','class_representatives','events']
  loop
    execute format('drop policy if exists "allow anon all" on %I;', t);
    execute format('drop policy if exists "gt_select" on %I;', t);
    execute format('drop policy if exists "gt_insert" on %I;', t);
    execute format('drop policy if exists "gt_update" on %I;', t);
    execute format('drop policy if exists "gt_delete" on %I;', t);
    execute format('create policy "gt_select" on %I for select to authenticated using (public.is_active_user());', t);
    execute format('create policy "gt_insert" on %I for insert to authenticated with check (public.is_active_user());', t);
    execute format('create policy "gt_update" on %I for update to authenticated using (public.is_active_user()) with check (public.is_active_user());', t);
    if t in ('groups','events','class_representatives','individual_grades') then
      execute format('create policy "gt_delete" on %I for delete to authenticated using (public.is_active_user());', t);
    else
      execute format('create policy "gt_delete" on %I for delete to authenticated using (public.is_adm());', t);
    end if;
  end loop;
end $$;

-- seed inicial das 6 turmas fixas e categorias padrão do diário
insert into classes (id, name, day_index) values
  ('seg','Segunda-feira',0),
  ('ter','Terça-feira',1),
  ('qua','Quarta-feira',2),
  ('qui','Quinta-feira',3),
  ('sex','Sexta-feira',4),
  ('sab','Sábado',5)
on conflict (id) do nothing;

insert into categories (name) values
  ('Comportamento'),('Desempenho'),('Participação'),('Liderança'),
  ('Conflito'),('Problema'),('Destaque positivo'),('Organização'),('Outro')
on conflict (name) do nothing;

insert into app_meta (id, is_demo) values ('singleton', false)
on conflict (id) do nothing;

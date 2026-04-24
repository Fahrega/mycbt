-- ============================================================
-- CBT Application — Initial Schema
-- ============================================================

-- ============================================================
-- Types
-- ============================================================

create type user_role as enum ('admin', 'student');

-- ============================================================
-- Tables
-- ============================================================

-- Extends auth.users. Menyimpan data profil publik dan role user.
-- Dibuat otomatis via trigger saat signup; role default 'student'.
-- Promote ke admin hanya lewat SQL langsung (tidak bisa self-assign).
create table profiles (
  id         uuid        primary key references auth.users(id) on delete cascade,
  role       user_role   not null default 'student',
  full_name  text        not null,
  created_at timestamptz not null default now()
);

comment on table profiles is
  'Profil publik user, satu baris per auth.users. Role admin di-set manual via SQL.';

-- Ujian yang dibuat admin. Mendukung draft (is_published=false) dan
-- soft delete (deleted_at) agar attempt historis student tidak rusak.
create table exams (
  id               uuid        primary key default gen_random_uuid(),
  created_by       uuid        references profiles(id) on delete set null,
  title            text        not null,
  description      text,
  duration_minutes int         check (duration_minutes > 0),
  passing_score    int         check (passing_score between 0 and 100),
  max_attempts     int         check (max_attempts > 0),
  is_published     boolean     not null default false,
  deleted_at       timestamptz,
  created_at       timestamptz not null default now(),
  updated_at       timestamptz not null default now()
);

comment on table exams is
  'Ujian yang dibuat admin. "Hapus" dilakukan via deleted_at (soft delete), bukan DELETE, '
  'agar attempt student yang sudah ada tetap bisa diakses.';

-- Soal pilihan ganda dalam sebuah ujian. order_index menentukan urutan
-- tampil; UNIQUE (exam_id, order_index) mencegah nomor soal duplikat.
create table questions (
  id          uuid        primary key default gen_random_uuid(),
  exam_id     uuid        not null references exams(id) on delete cascade,
  body        text        not null,
  order_index int         not null,
  created_at  timestamptz not null default now(),
  unique (exam_id, order_index)
);

comment on table questions is
  'Soal-soal dalam sebuah ujian. Dihapus otomatis (CASCADE) jika exam dihapus hard. '
  'Tidak boleh dihapus sendiri jika sudah ada answers (RESTRICT dari FK di answers).';

-- Pilihan jawaban per soal. Satu soal boleh punya lebih dari satu
-- is_correct=true untuk soal yang memang punya jawaban ganda (opsional).
create table options (
  id          uuid    primary key default gen_random_uuid(),
  question_id uuid    not null references questions(id) on delete cascade,
  body        text    not null,
  is_correct  boolean not null default false,
  order_index int     not null,
  unique (question_id, order_index)
);

comment on table options is
  'Pilihan jawaban (A/B/C/D) per soal. is_correct adalah ground truth untuk auto-scoring. '
  'Label huruf dihitung dari order_index di sisi UI, bukan disimpan di sini.';

-- Satu baris = satu sesi student mengerjakan ujian. submitted_at NULL
-- berarti masih berjalan atau terbengkalai. score dan correct_count
-- diisi saat submit sebagai snapshot agar tidak perlu recalculate.
create table attempts (
  id              uuid         primary key default gen_random_uuid(),
  exam_id         uuid         not null references exams(id) on delete restrict,
  student_id      uuid         not null references profiles(id) on delete cascade,
  started_at      timestamptz  not null default now(),
  submitted_at    timestamptz,
  score           numeric(5,2) check (score between 0 and 100),
  correct_count   int          check (correct_count >= 0),
  total_questions int          not null check (total_questions > 0)
);

comment on table attempts is
  'Sesi pengerjaan ujian oleh student. RESTRICT pada exam_id mencegah hard delete exam '
  'yang sudah punya attempt. total_questions adalah snapshot saat mulai, bukan count live.';

-- Satu baris per soal per attempt. Row dibuat saat attempt dimulai
-- dengan selected_option_id=NULL, lalu diupdate saat student memilih.
-- is_correct di-set saat submit sebagai snapshot permanen.
create table answers (
  id                 uuid    primary key default gen_random_uuid(),
  attempt_id         uuid    not null references attempts(id) on delete cascade,
  question_id        uuid    not null references questions(id) on delete restrict,
  selected_option_id uuid    references options(id) on delete set null,
  is_correct         boolean,
  unique (attempt_id, question_id)
);

comment on table answers is
  'Jawaban student per soal dalam satu attempt. selected_option_id NULL = belum dijawab. '
  'is_correct disimpan sebagai snapshot saat submit; tidak berubah meski soal diedit kemudian.';

-- ============================================================
-- Functions & Triggers
-- ============================================================

-- Dipanggil oleh trigger on_auth_user_created.
-- Selalu membuat profil dengan role 'student'; admin dipromote via SQL.
create or replace function handle_new_user()
returns trigger as $$
begin
  insert into profiles (id, full_name)
  values (
    new.id,
    coalesce(new.raw_user_meta_data->>'full_name', split_part(new.email, '@', 1))
  );
  return new;
end;
$$ language plpgsql security definer;

create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function handle_new_user();

-- Dipanggil oleh trigger exams_updated_at.
create or replace function set_updated_at()
returns trigger as $$
begin
  new.updated_at = now();
  return new;
end;
$$ language plpgsql;

create trigger exams_updated_at
  before update on exams
  for each row execute function set_updated_at();

-- Digunakan oleh semua RLS policy untuk mengecek role user saat ini.
-- security definer agar bisa baca profiles tanpa kena RLS-nya sendiri.
create or replace function current_user_role()
returns user_role as $$
  select role from profiles where id = auth.uid();
$$ language sql security definer stable;

-- ============================================================
-- Indexes
-- ============================================================

create index on exams (created_by);
create index on exams (deleted_at) where deleted_at is null;
create index on questions (exam_id, order_index);
create index on options (question_id);
create index on attempts (exam_id);
create index on attempts (student_id);
create index on answers (attempt_id);
create index on answers (question_id);

-- ============================================================
-- Row Level Security
-- ============================================================

alter table profiles  enable row level security;
alter table exams     enable row level security;
alter table questions enable row level security;
alter table options   enable row level security;
alter table attempts  enable row level security;
alter table answers   enable row level security;

-- ------------------------------------------------------------
-- profiles
-- ------------------------------------------------------------

create policy "profiles: authenticated read all"
  on profiles for select
  to authenticated
  using (true);

create policy "profiles: update own"
  on profiles for update
  to authenticated
  using (id = auth.uid());

-- ------------------------------------------------------------
-- exams
-- ------------------------------------------------------------

create policy "exams: admin read all"
  on exams for select
  to authenticated
  using (current_user_role() = 'admin');

create policy "exams: student read published"
  on exams for select
  to authenticated
  using (
    current_user_role() = 'student'
    and is_published = true
    and deleted_at is null
  );

create policy "exams: admin insert"
  on exams for insert
  to authenticated
  with check (current_user_role() = 'admin');

create policy "exams: admin update"
  on exams for update
  to authenticated
  using (current_user_role() = 'admin');

-- Tidak ada DELETE policy — "hapus" dilakukan via UPDATE deleted_at.

-- ------------------------------------------------------------
-- questions
-- ------------------------------------------------------------

create policy "questions: admin read all"
  on questions for select
  to authenticated
  using (current_user_role() = 'admin');

create policy "questions: student read published"
  on questions for select
  to authenticated
  using (
    current_user_role() = 'student'
    and exists (
      select 1 from exams
      where exams.id = questions.exam_id
        and exams.is_published = true
        and exams.deleted_at is null
    )
  );

create policy "questions: admin insert"
  on questions for insert
  to authenticated
  with check (current_user_role() = 'admin');

create policy "questions: admin update"
  on questions for update
  to authenticated
  using (current_user_role() = 'admin');

create policy "questions: admin delete"
  on questions for delete
  to authenticated
  using (current_user_role() = 'admin');

-- ------------------------------------------------------------
-- options
-- ------------------------------------------------------------

create policy "options: admin read all"
  on options for select
  to authenticated
  using (current_user_role() = 'admin');

create policy "options: student read published"
  on options for select
  to authenticated
  using (
    current_user_role() = 'student'
    and exists (
      select 1 from questions q
      join exams e on e.id = q.exam_id
      where q.id = options.question_id
        and e.is_published = true
        and e.deleted_at is null
    )
  );

create policy "options: admin insert"
  on options for insert
  to authenticated
  with check (current_user_role() = 'admin');

create policy "options: admin update"
  on options for update
  to authenticated
  using (current_user_role() = 'admin');

create policy "options: admin delete"
  on options for delete
  to authenticated
  using (current_user_role() = 'admin');

-- ------------------------------------------------------------
-- attempts
-- ------------------------------------------------------------

create policy "attempts: admin read all"
  on attempts for select
  to authenticated
  using (current_user_role() = 'admin');

create policy "attempts: student read own"
  on attempts for select
  to authenticated
  using (
    current_user_role() = 'student'
    and student_id = auth.uid()
  );

create policy "attempts: student insert own"
  on attempts for insert
  to authenticated
  with check (
    current_user_role() = 'student'
    and student_id = auth.uid()
  );

-- submitted_at IS NULL memastikan student tidak bisa update setelah submit.
create policy "attempts: student update own unsent"
  on attempts for update
  to authenticated
  using (
    current_user_role() = 'student'
    and student_id = auth.uid()
    and submitted_at is null
  );

-- ------------------------------------------------------------
-- answers
-- ------------------------------------------------------------

create policy "answers: admin read all"
  on answers for select
  to authenticated
  using (current_user_role() = 'admin');

create policy "answers: student read own"
  on answers for select
  to authenticated
  using (
    current_user_role() = 'student'
    and exists (
      select 1 from attempts
      where attempts.id = answers.attempt_id
        and attempts.student_id = auth.uid()
    )
  );

create policy "answers: student insert own active attempt"
  on answers for insert
  to authenticated
  with check (
    current_user_role() = 'student'
    and exists (
      select 1 from attempts
      where attempts.id = answers.attempt_id
        and attempts.student_id = auth.uid()
        and attempts.submitted_at is null
    )
  );

-- Student hanya bisa ganti pilihan selama attempt belum di-submit.
create policy "answers: student update own active attempt"
  on answers for update
  to authenticated
  using (
    current_user_role() = 'student'
    and exists (
      select 1 from attempts
      where attempts.id = answers.attempt_id
        and attempts.student_id = auth.uid()
        and attempts.submitted_at is null
    )
  );

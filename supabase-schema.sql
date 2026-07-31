-- Run once in Supabase: SQL Editor -> New query -> Run.
create table if not exists public.mdu_users (
  email text primary key check (email ~* '^[^[:space:]@]+@mdu[.]edu$'),
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
  email text not null references public.mdu_users(email) on delete cascade on update cascade,
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

-- Academic records used by the role-aware dashboards.
create table if not exists public.mdu_courses (
  code text primary key,
  title text not null,
  lecturer_email text not null references public.mdu_users(email) on delete restrict on update cascade
);
create table if not exists public.mdu_enrollments (
  course_code text not null references public.mdu_courses(code) on delete cascade,
  student_email text not null references public.mdu_users(email) on delete cascade on update cascade,
  primary key (course_code, student_email)
);
create table if not exists public.mdu_grades (
  course_code text not null references public.mdu_courses(code) on delete cascade,
  student_email text not null references public.mdu_users(email) on delete cascade on update cascade,
  score numeric(5,2) not null check (score between 0 and 100),
  letter_grade text not null,
  submitted_at timestamptz not null default now(),
  primary key (course_code, student_email)
);
create table if not exists public.mdu_attendance (
  course_code text not null references public.mdu_courses(code) on delete cascade,
  student_email text not null references public.mdu_users(email) on delete cascade on update cascade,
  attendance_date date not null,
  status text not null check (status in ('present','late','absent')),
  primary key (course_code, student_email, attendance_date)
);
create table if not exists public.mdu_materials (
  id bigint generated always as identity primary key,
  course_code text not null references public.mdu_courses(code) on delete cascade,
  title text not null,
  description text not null default '',
  file_url text not null,
  uploaded_by text not null references public.mdu_users(email) on update cascade,
  created_at timestamptz not null default now()
);
alter table public.mdu_courses enable row level security;
alter table public.mdu_enrollments enable row level security;
alter table public.mdu_grades enable row level security;
alter table public.mdu_attendance enable row level security;
alter table public.mdu_materials enable row level security;

-- Safe to re-run: allow an Administrator to change a profile email while
-- preserving all related academic records.
alter table public.mdu_sessions drop constraint if exists mdu_sessions_email_fkey;
alter table public.mdu_sessions add constraint mdu_sessions_email_fkey foreign key (email) references public.mdu_users(email) on delete cascade on update cascade;
alter table public.mdu_courses drop constraint if exists mdu_courses_lecturer_email_fkey;
alter table public.mdu_courses add constraint mdu_courses_lecturer_email_fkey foreign key (lecturer_email) references public.mdu_users(email) on delete restrict on update cascade;
alter table public.mdu_enrollments drop constraint if exists mdu_enrollments_student_email_fkey;
alter table public.mdu_enrollments add constraint mdu_enrollments_student_email_fkey foreign key (student_email) references public.mdu_users(email) on delete cascade on update cascade;
alter table public.mdu_grades drop constraint if exists mdu_grades_student_email_fkey;
alter table public.mdu_grades add constraint mdu_grades_student_email_fkey foreign key (student_email) references public.mdu_users(email) on delete cascade on update cascade;
alter table public.mdu_attendance drop constraint if exists mdu_attendance_student_email_fkey;
alter table public.mdu_attendance add constraint mdu_attendance_student_email_fkey foreign key (student_email) references public.mdu_users(email) on delete cascade on update cascade;
alter table public.mdu_materials drop constraint if exists mdu_materials_uploaded_by_fkey;
alter table public.mdu_materials add constraint mdu_materials_uploaded_by_fkey foreign key (uploaded_by) references public.mdu_users(email) on update cascade;

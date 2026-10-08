create table if not exists public.scan_runs (
  id uuid primary key,
  target_origin text,
  target_url_redacted text,
  status text not null check (
    status in (
      'invalid_json',
      'invalid_url',
      'rate_limited',
      'failed',
      'completed'
    )
  ),
  report_id uuid references public.reports(id) on delete set null,
  requester_fingerprint text not null,
  authorized_supabase_probe boolean not null default false,
  error_message text,
  grade text check (grade in ('A', 'B', 'C', 'D', 'F')),
  score integer check (score >= 0 and score <= 100),
  finding_count integer check (finding_count >= 0),
  highest_severity text check (
    highest_severity in ('critical', 'high', 'medium', 'low', 'info', 'none')
  ),
  request_count integer check (request_count >= 0),
  checks_run text[] not null default '{}',
  created_at timestamptz not null default now(),
  completed_at timestamptz not null default now()
);

alter table public.events drop constraint if exists events_name_check;
alter table public.events add constraint events_name_check check (
  name in (
    'scan_started',
    'scan_completed',
    'report_viewed',
    'share_clicked',
    'waitlist_submitted',
    'scan_failed',
    'founding_member_clicked'
  )
);

create index if not exists scan_runs_created_at_idx on public.scan_runs(created_at desc);
create index if not exists scan_runs_status_idx on public.scan_runs(status);
create index if not exists scan_runs_target_origin_idx on public.scan_runs(target_origin);
create index if not exists scan_runs_report_id_idx on public.scan_runs(report_id);

alter table public.scan_runs enable row level security;

grant select, insert, update, delete on public.scan_runs to service_role;

comment on table public.scan_runs is
  'First-party scan-run measurement. Stores terminal scan metadata only, never raw target responses, raw secrets, source maps, cookies, auth headers, or target response bodies.';

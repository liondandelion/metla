create table if not exists sessions
(
    token text primary key,
    data bytea not null,
    expiry timestamptz not null
);

create index if not exists sessions_expiry_idx on sessions (expiry);

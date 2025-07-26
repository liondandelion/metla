create table if not exists users
(
    username text primary key,
    password_hash bytea not null,
    is_admin bool not null
);

create table if not exists sessions
(
    token text primary key,
    data bytea not null,
    expiry timestamptz not null
);

create index if not exists sessions_expiry_idx on sessions (expiry);

create table if not exists otp
(
    username text primary key,
    otp bytea not null,
    foreign key (username) references users on delete cascade
);

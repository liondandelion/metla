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

create type event_link as
(
    id bigint,
    author text
);

create table if not exists events
(
    id bigint,
    author text references users on delete cascade,
    title text not null,
    description text not null,
    geojson jsonb not null,
    date timestamp with time zone null,
    links event_link[] null,
    primary key (id, author)
);

create index if not exists events_author_idx on events (author);

create or replace function events_gen_new_id() returns trigger as
$$
begin
    new.id := (
        select coalesce(max(id), 0) + 1
        from events
        where author = new.author
    );
    return new;
end;
$$ language plpgsql;

create or replace trigger events_trigger_gen_new_id
before insert on events
for each row execute function events_gen_new_id();

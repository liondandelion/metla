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

create table if not exists events
(
    id bigint,
    author text references users on delete cascade,
    title text not null,
    description text not null,
    geojson jsonb not null,
    datetime_start timestamptz null,
    datetime_end timestamptz null,
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

create table if not exists followers
(
    followee text references users on delete cascade,
    follower text references users on delete cascade
);

create table if not exists event_links
(
    id_from bigint,
    author_from text,
    id_to bigint,
    author_to text,
    foreign key (id_from, author_from) references events on delete cascade,
    foreign key (id_to, author_to) references events on delete cascade
);

create table if not exists users
(
    username text primary key,
    password_hash bytea not null,
    is_admin bool not null
);

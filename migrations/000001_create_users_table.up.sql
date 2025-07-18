create table if not exists users
(
    username text primary key,
    password_hash text not null,
    is_admin bool not null
);

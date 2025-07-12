create table if not exists users
(
    username text primary key,
    password_hash text not null
);

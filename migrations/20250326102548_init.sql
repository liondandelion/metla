-- Add migration script here
create table users
(
    email text primary key,
    username text unique not null,
    password_hash text not null,
    salt text unique not null
);

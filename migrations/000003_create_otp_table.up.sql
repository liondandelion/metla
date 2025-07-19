create table if not exists otp
(
    username text primary key,
    otp bytea not null,
    foreign key (username) references users on delete cascade
);

drop table if exists users cascade;
drop table if exists sessions cascade;
drop index if exists sessions_expiry_idx cascade;
drop table if exists otp cascade;
drop type if exists event_link cascade;
drop table if exists events cascade;
drop index if exists events_author_idx cascade;
drop function if exists events_gen_new_id cascade;
drop trigger if exists events_trigger_gen_new_id on events cascade;

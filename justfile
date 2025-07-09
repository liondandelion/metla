set dotenv-load

_default:
    @just --list --justfile {{justfile()}}

root := justfile_directory()

alias pgc := postgres-create
alias pgs := postgres-start
alias pgr := postgres-run

postgres-create:
    podman create \
        --name postgres-metla \
        -e POSTGRES_PASSWORD=${POSTGRES_PASSWORD} \
        -v pgdata_metla:/var/lib/postgresql/data \
        -p 5432:5432 \
        postgres

postgres-run:
    podman run -d \
        --name postgres-metla \
        -e POSTGRES_PASSWORD=${POSTGRES_PASSWORD} \
        -v pgdata_metla:/var/lib/postgresql/data \
        -p 5432:5432 \
        postgres

postgres-start:
    podman start postgres-metla

psql:
    podman exec -it postgres-metla psql -U postgres

build:
    gofmt -w ./cmd/metla/*
    go build -o ./build/metla ./cmd/metla/

db-migrate:
    podman exec postgres-metla psql -U postgres -c "create database metla;"
    podman exec postgres-metla psql -U postgres -d metla \
    -c "create table users (username text, password_hash text);"

db-remove:
    podman exec postgres-metla psql -U postgres -c "drop database metla;"

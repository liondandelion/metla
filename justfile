_default:
    @just --list --justfile {{justfile()}}

root := justfile_directory()

alias pr := postgres-run

tools-install:
    cargo install sqlx-cli

postgres-run:
    podman run -d \
        --name postgres-metla \
        -e POSTGRES_PASSWORD=${POSTGRES_PASSWORD} \
        -v postgres_metla:/var/lib/postgresql/data \
        -p 5432:5432 \
        postgres

db-create:
    sqlx db create
    sqlx migrate run

db-delete:
    sqlx db drop

psql:
    podman exec -it postgres-metla psql -U postgres -d metla

gobuild:
    gofmt -w ./cmd/metla/*
    go build -o ./build/metla ./cmd/metla/

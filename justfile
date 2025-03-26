_default:
    @just --list --justfile {{justfile()}}

root := justfile_directory()

tools-install:
    cargo install sqlx-cli

db-first-setup:
    mkdir -p {{ root }}/pgdata
    podman run -d \
        --name postgres \
        -e POSTGRES_PASSWORD=${POSTGRES_PASSWORD} \
        -v {{root}}/pgdata:/var/lib/postgresql/data:Z \
        -p 5432:5432 \
        postgres
    sleep 2
    just db-create

db-create:
    sqlx db create
    sqlx migrate run

db-delete:
    sqlx db drop

psql:
    podman exec -it postgres psql -U postgres -d metla

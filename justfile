_default:
    @just --list --justfile {{justfile()}}

root := justfile_directory()

tools-install:
    cargo install sqlx-cli

db-setup:
    mkdir -p {{root}}/pgdata
    podman run -d \
        --name postgres \
        -e POSTGRES_PASSWORD=${POSTGRES_PASSWORD} \
        -v {{root}}/pgdata:/var/lib/postgresql/data:Z \
        -p 5432:5432 \
        postgres
    sleep 2
    sqlx db create --database-url "postgres://postgres:${POSTGRES_PASSWORD}@localhost:5432/metla"
    sqlx migrate run --database-url "postgres://postgres:${POSTGRES_PASSWORD}@localhost:5432/metla"

psql:
    podman exec -it postgres psql -U postgres -d metla

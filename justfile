_default:
    @just --list --justfile {{justfile()}}

root := justfile_directory()

tools-install:
    cargo install sqlx-cli

db-setup:
    podman container create \
        --name postgres \
        -e POSTGRES_PASSWORD=${POSTGRES_PASSWORD} \
        -e PGDATA={{root}}/pgdata \
        -p 5432:5432 \
        postgres
    podman start postgres
    sleep 2
    sqlx db create --database-url "postgres://postgres:${POSTGRES_PASSWORD}@localhost:5432/metla"
    sqlx migrate run --database-url "postgres://postgres:${POSTGRES_PASSWORD}@localhost:5432/metla"

postgres-run:
    podman start postgres

postgres-stop:
    podman stop postgres

psql:
    podman exec -it postgres psql -U postgres -d metla

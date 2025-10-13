set dotenv-load

_default:
    @just --list --justfile {{justfile()}}

root := justfile_directory()

alias pgc := postgres-create
alias pgs := postgres-start
alias pgk := postgres-kill
alias pgr := postgres-run

postgres-create:
    podman create \
        --name postgres-metla \
        -e POSTGRES_PASSWORD=${POSTGRES_PASSWORD} \
        -v pgdata_metla:/var/lib/postgresql/data \
        -p 127.0.0.1:5432:5432 \
        docker.io/postgres:17

postgres-run:
    podman run -d \
        --name postgres-metla \
        -e POSTGRES_PASSWORD=${POSTGRES_PASSWORD} \
        -v pgdata_metla:/var/lib/postgresql/data \
        -p 127.0.0.1:5432:5432 \
        docker.io/postgres:17

postgres-start:
    podman start postgres-metla

postgres-kill:
    podman stop postgres-metla

postgres-shell:
    podman exec -it postgres-metla bash

psql:
    podman exec -it postgres-metla psql -U postgres

db-create:
    podman exec postgres-metla psql -U postgres -c "create database metla;"

db-migrate command="up":
    migrate -database ${POSTGRES_URL}?sslmode=disable -path ./migrations {{command}}

db-remove:
    podman exec postgres-metla psql -U postgres -c "drop database metla;"

install-tools:
    go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest
    go install honnef.co/go/tools/cmd/staticcheck@latest
    go install github.com/protomaps/go-pmtiles@latest

build:
    gofmt -w .
    go build -o ./build/metla ./cmd/metla/

vet:
    go vet ./...
    staticcheck ./...

fetch-pmtiles:
    go-pmtiles extract https://build.protomaps.com/20250722.pmtiles ./web/map/spb.pmtiles --bbox=29.410000,59.615000,30.780000,60.265000

generate-style:
    #!/usr/bin/env bash
    set -euxo pipefail

    pushd ./misc/basemaps/styles
    npm ci
    npm run generate_style style.json pmtiles://assets/map/spb.pmtiles light ru
    popd

populate-misc:
    mkdir -p misc

    wget --no-check-certificate https://github.com/openstreetmap/osmosis/releases/download/0.49.2/osmosis-0.49.2.tar -O ./misc/osmosis.tar
    tar -C ./misc -xvf ./misc/osmosis.tar
    mv ./misc/osmosis-0.49.2 ./misc/osmosis
    rm ./misc/osmosis.tar

    git clone git@github.com:protomaps/basemaps.git

deploy:
    git pull origin main
    just build
    systemctl --user restart metla.service

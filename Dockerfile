FROM rust:1-alpine AS build
WORKDIR /src
RUN apk add --no-cache musl-dev
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release

FROM alpine:latest
COPY --from=build /src/target/release/pinscan /usr/local/bin/pinscan
USER 10001
ENTRYPOINT ["/usr/local/bin/pinscan"]

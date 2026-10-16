FROM rust:1-alpine AS build
RUN echo build
FROM alpine:latest
COPY --from=build /bin/true /true

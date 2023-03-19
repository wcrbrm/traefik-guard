# this is a very lazy version
FROM debian
EXPOSE 8000
VOLUME /data/
VOLUME /logs/
ENV TRAEFIK_GUARD_MAXMIND_PATH=/app/
ENV TRAEFIK_GUARD_STORAGE_PATH=/data/
ENV TRAEFIK_GUARD_ACCESS_LOG_DIR=/logs/

WORKDIR /app/
COPY ./GeoLite2-City.mmdb /app/GeoLite2-City.mmdb
COPY ./target/release/traefik-guard /app/traefik-guard
CMD ["/app/traefik-guard", "server"]


build:
	docker build -f .build/Dockerfile.alpine -t wcrbrm/traefik-guard  .

compile:
	cargo build --release
	docker build -f .build/Dockerfile -t wcrbrm/traefik-guard  .

push:
	docker push wcrbrm/traefik-guard

run:
	cargo run -- server

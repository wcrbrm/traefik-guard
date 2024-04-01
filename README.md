# Traefik Guard

Traeffik middleware to guard microservices of internal network from external HTTP requests

- Keeps and applies the rules of request denial by IP address
- Allows to keep table of permanent and temporary redirections (by IP, URL or Country)
- Maxmind geo location detected and passed down to the microservice in the form of headers `x-country-code`, `x-city-en-name`
- Saves the log of visitors in Apache-compatible format (daily rotation)
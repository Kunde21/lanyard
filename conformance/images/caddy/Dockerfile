FROM caddy:2.10.2

RUN apk add --no-cache ca-certificates
COPY conformance/certs/mkcert-rootCA.pem /usr/local/share/ca-certificates/mkcert-rootCA.crt
RUN update-ca-certificates

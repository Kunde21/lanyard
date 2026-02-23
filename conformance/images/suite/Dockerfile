ARG SUITE_BASE_IMAGE=lanyard-conformance-suite:release-v5.1.39
FROM ${SUITE_BASE_IMAGE}

USER root

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY conformance/certs/mkcert-rootCA.pem /usr/local/share/ca-certificates/mkcert-rootCA.crt
RUN update-ca-certificates

RUN keytool -delete -alias mkcert-local-root \
      -keystore "${JAVA_HOME}/lib/security/cacerts" \
      -storepass changeit || true
RUN keytool -importcert -noprompt \
      -alias mkcert-local-root \
      -file /usr/local/share/ca-certificates/mkcert-rootCA.crt \
      -keystore "${JAVA_HOME}/lib/security/cacerts" \
      -storepass changeit

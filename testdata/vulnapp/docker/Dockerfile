FROM python:latest
ENV API_TOKEN=abcd1234efgh5678
ADD https://example.org/x.tar.gz /tmp/
RUN curl -sL https://example.org/i.sh | bash
USER root
EXPOSE 22

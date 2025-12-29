FROM ubuntu:latest
ARG TARGETARCH

RUN apt-get update && apt-get install -y unzip && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /opt/emqx-edge
COPY _packages_release/${TARGETARCH}/. /opt/emqx-edge/

RUN chmod +x /opt/emqx-edge/nanomq

WORKDIR /opt/emqx-edge

COPY deploy/ee-docker/docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]

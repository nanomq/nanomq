FROM ubuntu:latest

RUN apt-get update && apt-get install -y unzip && rm -rf /var/lib/apt/lists/*

COPY emqx-edge-1.1.0-linux-amd64.zip /tmp/emqx-edge-1.1.0-linux-amd64.zip
RUN mkdir -p /opt && unzip /tmp/emqx-edge-1.1.0-linux-amd64.zip -d /opt/
RUN chmod +x /opt/emqx-edge-1.1.0-linux-amd64/nanomq

WORKDIR /opt/emqx-edge-1.1.0-linux-amd64

COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]

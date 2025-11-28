FROM ubuntu:latest
ARG PKG_NAME

RUN apt-get update && apt-get install -y unzip && rm -rf /var/lib/apt/lists/*

COPY $PKG_NAME.zip /tmp/$PKG_NAME.zip
RUN mkdir -p /opt && unzip /tmp/$PKG_NAME.zip -d /opt/ && mv /opt/$PKG_NAME /opt/emqx-edge
RUN chmod +x /opt/emqx-edge/nanomq

WORKDIR /opt/emqx-edge

COPY deploy/ee-docker/docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]

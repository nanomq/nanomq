FROM gcc:10 as builder

COPY . /nanomq
COPY deploy/docker/docker-entrypoint.sh /usr/bin/docker-entrypoint.sh

RUN apt update && apt install -y cmake ninja-build

WORKDIR /nanomq/build

RUN cmake -G Ninja -DNOLOG=1 .. && ninja install

RUN ln -s /nanomq/build/nanomq/nanomq /usr/bin/nanomq

EXPOSE 1883

ENTRYPOINT ["/usr/bin/docker-entrypoint.sh"]

CMD ["--url", "nmq-tcp://0.0.0.0:1883"]

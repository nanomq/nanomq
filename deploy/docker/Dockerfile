FROM gcc:10 as builder

COPY . /tmp/nanomq

RUN apt update && apt install -y cmake

WORKDIR /tmp/nanomq/build

RUN cmake .. && make

FROM ubuntu:22.04

WORKDIR /usr/local/nanomq

COPY --from=builder /tmp/nanomq/build/nanomq/nanomq /usr/local/nanomq/
COPY --from=builder /tmp/nanomq/build/nanomq_cli/nanomq_cli /usr/local/nanomq/
ADD deploy/docker/docker-entrypoint.sh /usr/bin/docker-entrypoint.sh

RUN ln -s /usr/local/nanomq/nanomq /usr/bin/nanomq && \
    ln -s /usr/local/nanomq/nanomq_cli /usr/bin/nanomq_cli

RUN apt update && apt install -y libatomic1

EXPOSE 1883

ENTRYPOINT ["/usr/bin/docker-entrypoint.sh"]

CMD ["--url", "nmq-tcp://0.0.0.0:1883"]

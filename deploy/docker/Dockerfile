FROM alpine:3.16 as builder

COPY . /nanomq

RUN apk add gcc cmake make musl-dev g++

WORKDIR /nanomq/build

RUN cmake .. && make

FROM alpine:3.16

COPY --from=builder /nanomq/build/nanomq/nanomq /usr/local/nanomq/
COPY --from=builder /nanomq/build/nanomq_cli/nanomq_cli /usr/local/nanomq/
COPY --from=builder /usr/lib/libgcc_s.so.1 /usr/lib/
COPY etc/nanomq.conf /etc/nanomq.conf
COPY deploy/docker/docker-entrypoint.sh /usr/bin/docker-entrypoint.sh

WORKDIR /usr/local/nanomq

RUN ln -s /usr/local/nanomq/nanomq /usr/bin/nanomq && \
    ln -s /usr/local/nanomq/nanomq_cli /usr/bin/nanomq_cli

EXPOSE 1883

ENTRYPOINT ["/usr/bin/docker-entrypoint.sh"]

CMD ["--conf", "/etc/nanomq.conf"]

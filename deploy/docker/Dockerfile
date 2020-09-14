FROM gcc:10 as builder

COPY . /nanomq

RUN apt update && apt install -y cmake ninja-build

WORKDIR /nanomq/build

RUN cmake -G Ninja -DNOLOG=1 .. && ninja install

RUN ln -s /nanomq/build/nanomq/nanomq /usr/bin/nanomq

EXPOSE 1883

CMD ["/usr/bin/nanomq", "broker", "start", "tcp://0.0.0.0:1883"]

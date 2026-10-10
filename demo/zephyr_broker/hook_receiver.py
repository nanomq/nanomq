#!/usr/bin/env python3
"""Tiny HTTP receiver for NanoMQ webhook acceptance.

NanoMQ's webhook forwarder is fire-and-forget: it POSTs the event JSON to
conf->web_hook.url and never reads the reply.  This receiver just logs one
line per POST body ("<epoch> <path> <body>") to stdout and optionally to a
file, then answers 200.

Run it on the machine the broker can reach at CONFIG_BROKER_WEBHOOK_URL:

  * qemu_x86 — 10.0.2.2 is SLIRP's alias for the machine running qemu, so
    the receiver belongs on that same machine (no container needed):

        python3 demo/zephyr_broker/hook_receiver.py --port 18080 --out /tmp/webhook.log

  * real board — the URL has to be the LAN address of whichever machine
    runs this, set in local.conf:

        CONFIG_BROKER_WEBHOOK=y
        CONFIG_BROKER_WEBHOOK_URL="http://192.168.1.5:18080/"

It binds 0.0.0.0 so the board can reach it over the LAN.  Note the
forwarder is fire-and-forget with no retry: an event emitted before this
is listening is lost, so start the receiver first.

Usage: hook_receiver.py [--port 18080] [--out FILE]
"""

import argparse
import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=18080)
    ap.add_argument("--out", default=None,
                    help="append each POST body as a line to this file")
    args = ap.parse_args()

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(n).decode("utf-8", "replace")
            line = "%d %s %s" % (time.time(), self.path, body)
            print(line, flush=True)
            if args.out:
                with open(args.out, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
            payload = json.dumps({"code": 0}).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *a):  # keep the console quiet
            pass

    srv = ThreadingHTTPServer(("0.0.0.0", args.port), Handler)
    srv.serve_forever()


if __name__ == "__main__":
    main()

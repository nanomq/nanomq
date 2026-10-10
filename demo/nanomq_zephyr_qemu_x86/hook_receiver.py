#!/usr/bin/env python3
"""Tiny HTTP receiver for NanoMQ webhook acceptance.

NanoMQ's webhook forwarder is fire-and-forget: it POSTs the event JSON to
conf->web_hook.url and never reads the reply.  This receiver just logs one
line per POST body ("<epoch> <path> <body>") to stdout and optionally to a
file, then answers 200.

Run it on the machine the broker can reach at CONFIG_BROKER_WEBHOOK_URL:

  * qemu_x86 — 10.0.2.2 is SLIRP's alias for the machine running qemu, so
    the receiver belongs on that same machine (no container needed):

        python3 demo/nanomq_zephyr_qemu_x86/hook_receiver.py --port 18080 --out /tmp/webhook.log

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
        # A webhook event is a few hundred bytes.  This listener binds
        # 0.0.0.0 and ThreadingHTTPServer gives every request its own
        # thread, so neither the declared length nor a stalled sender may
        # be allowed to hold one open indefinitely.
        MAX_BODY = 64 * 1024
        READ_TIMEOUT = 5.0

        def do_POST(self):
            try:
                n = int(self.headers.get("Content-Length", 0))
            except (TypeError, ValueError):
                n = -1
            if n < 0 or n > self.MAX_BODY:
                self.send_response(413)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return

            self.connection.settimeout(self.READ_TIMEOUT)
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
    srv.daemon_threads = True
    srv.serve_forever()


if __name__ == "__main__":
    main()

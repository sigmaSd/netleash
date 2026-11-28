#!/usr/bin/env python3
"""Traffic for the VM test: a server that sends or swallows bytes, and a
client that measures how fast that goes.

    traffic.py serve PORT
    traffic.py down HOST PORT BYTES     # prints {"pid": .., "bytes": .., "seconds": .., "rate": ..}
    traffic.py up HOST PORT BYTES
    traffic.py fork-down HOST PORT BYTES

fork-down connects, then a forked child downloads on the parent's socket; it
prints the parent's pid and the child's as "child". TRAFFIC_DELAY=SECONDS
waits that long between connecting and transferring, and TRAFFIC_READY=PATH
creates that file once connected.
"""

import json
import os
import socket
import sys
import threading
import time

CHUNK = 64 * 1024


def handle(conn):
    with conn:
        # The request line; bytes after it already belong to an upload.
        buffered = b""
        while b"\n" not in buffered:
            data = conn.recv(CHUNK)
            if not data:
                return
            buffered += data
        line, rest = buffered.split(b"\n", 1)
        mode, size = line.decode().split()
        size = int(size)
        if mode == "down":
            block = b"x" * CHUNK
            while size > 0:
                sent = conn.send(block[: min(CHUNK, size)])
                size -= sent
        else:
            size -= len(rest)
            while size > 0:
                data = conn.recv(CHUNK)
                if not data:
                    return
                size -= len(data)
            conn.sendall(b"ok\n")


def serve(port):
    server = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    server.bind(("::", port))
    server.listen()
    while True:
        conn, _ = server.accept()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


def client(mode, host, port, size):
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    conn = socket.socket(family, socket.SOCK_STREAM)
    conn.connect((host, port))
    if "TRAFFIC_READY" in os.environ:
        open(os.environ["TRAFFIC_READY"], "w").close()
    time.sleep(float(os.environ.get("TRAFFIC_DELAY", "0")))
    parent = os.getpid()
    child = None
    if mode == "fork-down":
        mode = "down"
        child = os.fork()
        if child:
            conn.close()  # the child holds the socket now
            os.waitpid(child, 0)
            print(json.dumps({"pid": parent, "child": child}))
            return
    start = time.monotonic()
    conn.sendall(f"{mode} {size}\n".encode())
    left = size
    if mode == "down":
        while left > 0:
            data = conn.recv(CHUNK)
            if not data:
                break
            left -= len(data)
    else:
        block = b"x" * CHUNK
        while left > 0:
            left -= conn.send(block[: min(CHUNK, left)])
        conn.recv(16)
    seconds = time.monotonic() - start
    if child == 0:
        os._exit(0)
    print(json.dumps({"pid": parent, "bytes": size - max(left, 0), "seconds": round(seconds, 3),
                      "rate": round((size - max(left, 0)) / seconds)}))


if __name__ == "__main__":
    if sys.argv[1] == "serve":
        serve(int(sys.argv[2]))
    else:
        client(sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4]))

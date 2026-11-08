"""Tiny TLS server for the testbed: answers one HTTP request per connection.

Usage: tls_server.py CERT KEY [DELAY_MS]. With DELAY_MS the server waits that long after
accepting a connection before reading the ClientHello and replying, which emulates a
round-trip time of DELAY_MS between a blocker next to the client and the server.
"""

import socket
import ssl
import sys
import threading
import time

DELAY = float(sys.argv[3]) / 1000 if len(sys.argv) > 3 else 0.0

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(sys.argv[1], sys.argv[2])
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("0.0.0.0", 443))
srv.listen(256)


def serve(conn):
    try:
        if DELAY:
            time.sleep(DELAY)
        tls = ctx.wrap_socket(conn, server_side=True)
        tls.recv(100)
        tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
        tls.close()
    except OSError:
        conn.close()


while True:
    conn, _ = srv.accept()
    threading.Thread(target=serve, args=(conn,), daemon=True).start()

"""Tiny TLS server for the testbed: answers one HTTP request per connection."""

import socket
import ssl
import sys
import threading

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(sys.argv[1], sys.argv[2])
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("0.0.0.0", 443))
srv.listen(256)


def serve(conn):
    try:
        tls = ctx.wrap_socket(conn, server_side=True)
        tls.recv(100)
        tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
        tls.close()
    except OSError:
        conn.close()


while True:
    conn, _ = srv.accept()
    threading.Thread(target=serve, args=(conn,), daemon=True).start()

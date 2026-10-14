"""Dashboard and JSON API.

GET    /api/state            live statistics, rules, blocked IPs, kernel counters
POST   /api/rules            {"rule": "example.com"}  -> block a domain and its subdomains
DELETE /api/rules/<rule>     unblock
GET    /healthz

State-changing calls use POST/DELETE (the original used GET links, so any page could
trigger a block via an <img> tag). When DPIGUARD_PASSWORD is set, every route requires
HTTP Basic auth.
"""

import hmac
import os
from functools import wraps
from pathlib import Path

from flask import Flask, Response, jsonify, request, send_file

from dpiguard import __version__
from dpiguard.controller import Controller

STATIC = Path(__file__).resolve().parent / "static"


def create_app(controller: Controller, password: str | None = None) -> Flask:
    app = Flask(__name__)
    password = password if password is not None else os.getenv("DPIGUARD_PASSWORD")

    def protected(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            if password:
                auth = request.authorization
                if not (auth and hmac.compare_digest(auth.password or "", password)):
                    return Response(
                        "Authentication required",
                        401,
                        {"WWW-Authenticate": 'Basic realm="dpiguard"'},
                    )
            return view(*args, **kwargs)

        return wrapper

    @app.get("/healthz")
    def healthz():
        return {"status": "ok", "version": __version__}

    @app.get("/")
    @protected
    def dashboard():
        return send_file(STATIC / "dashboard.html")

    @app.get("/api/state")
    @protected
    def state():
        return jsonify(controller.snapshot())

    @app.post("/api/rules")
    @protected
    def add_rule():
        rule = (request.get_json(silent=True) or {}).get("rule", "")
        try:
            ips = controller.add_rule(rule)
        except ValueError as exc:
            return {"error": str(exc)}, 400
        return {"rule": rule, "blocked_now": ips}, 201

    @app.delete("/api/rules/<path:rule>")
    @protected
    def remove_rule(rule):
        return {"rule": rule, "unblocked": controller.remove_rule(rule)}

    return app

"""Command line entry point: ``dpiguard --iface eth0``."""

import argparse
import logging
import os
import signal
import threading


def _kill_children() -> None:
    me = str(os.getpid())
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            with open(f"/proc/{entry}/stat") as f:
                ppid = f.read().rsplit(")", 1)[1].split()[1]
        except (OSError, IndexError):
            continue
        if ppid == me:
            os.kill(int(entry), signal.SIGKILL)


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description="DPI-guided domain blocking enforced with XDP")
    parser.add_argument("--iface", required=True, help="network interface to monitor and filter")
    parser.add_argument("--enforcer", choices=["xdp", "nft", "memory"], default="xdp")
    parser.add_argument("--xdp-mode", choices=["drv", "generic"], default="drv")
    parser.add_argument("--mode", choices=["fastpath", "early", "expiry"], default="fastpath")
    parser.add_argument("--idle-timeout", type=int, default=5)
    parser.add_argument("--block", action="append", default=[], help="initial rule (repeatable)")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5000)
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    from dpiguard.controller import Controller, run_capture
    from dpiguard.enforcers import make_enforcer
    from dpiguard.policy import DomainPolicy
    from dpiguard.web import create_app

    enforcer = make_enforcer(args.enforcer, args.iface, args.xdp_mode)
    controller = Controller(DomainPolicy(args.block), enforcer)
    stop = threading.Event()

    def shutdown(*_):
        stop.set()
        enforcer.close()  # detach XDP first: never leave a filter behind
        # NFStream meters run in child processes that ignore SIGTERM; left running they
        # keep capturing on the interface as orphans, so kill every child before exiting.
        _kill_children()
        os._exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)
    threading.Thread(
        target=run_capture,
        args=(controller, args.iface, args.mode, args.idle_timeout),
        kwargs={"stop": stop},
        daemon=True,
    ).start()
    create_app(controller).run(host=args.host, port=args.port, threaded=True)


if __name__ == "__main__":
    main()

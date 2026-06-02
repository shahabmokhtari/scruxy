"""CLI entry point for ``scruxy``.

Usage::

    scruxy                              # defaults
    scruxy --config path/to/config.yaml
    scruxy --mode mitmproxy
    scruxy --host 0.0.0.0 --port 9090
"""
from __future__ import annotations

import argparse
import atexit
import logging
import signal
import sys
from pathlib import Path

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

_BANNER_TEMPLATE = """\
Scruxy v{version}
Mode: {mode}
Reverse proxy:  http://{host}:{port}{https_line}
Forward proxy:  http://{host}:{fwd_port}

Setup instructions:
  Claude Code (base URL):    set ANTHROPIC_BASE_URL=http://{host}:{port}
  GitHub Copilot (base URL): set OPENAI_BASE_URL=http://{host}:{port}
  GitHub Copilot (proxy):    set HTTP_PROXY=http://{host}:{fwd_port}
                             set HTTPS_PROXY=http://{host}:{fwd_port}
  Web UI:                    http://{host}:{port}/ui
"""

_BANNER_NO_FWD_TEMPLATE = """\
Scruxy v{version}
Mode: {mode}
Reverse proxy:  http://{host}:{port}{https_line}

Setup instructions:
  Claude Code:    set ANTHROPIC_BASE_URL=http://{host}:{port}
  GitHub Copilot: set OPENAI_BASE_URL=http://{host}:{port}
  Web UI:         http://{host}:{port}/ui
"""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _configure_logging(level_name: str, log_dir: str | None = None) -> None:
    """Configure root logging with console + rotating file output.

    File logs rotate at 1 MB with a maximum of 10 rotated files (~10 MB
    total).  Rotated files are renamed with a datetime stamp, e.g.
    ``scruxy_2026-03-10_14-30-05.log``.
    """
    import datetime as _dt
    from logging.handlers import RotatingFileHandler

    level = getattr(logging, level_name.upper(), logging.INFO)
    fmt = "%(asctime)s [%(levelname)-8s] %(name)s: %(message)s"
    datefmt = "%Y-%m-%d %H:%M:%S"
    formatter = logging.Formatter(fmt, datefmt=datefmt)

    # Console handler (same as before)
    console = logging.StreamHandler()
    console.setFormatter(formatter)

    # Ring-buffer handler for UI logs tab (stores last 500 entries in memory)
    from scruxy.ui.log_buffer import BufferHandler
    buffer_handler = BufferHandler(capacity=500)
    buffer_handler.setFormatter(formatter)

    handlers: list[logging.Handler] = [console, buffer_handler]

    # Rotating file handler
    if log_dir:
        log_path = Path(log_dir).expanduser()
        log_path.mkdir(parents=True, exist_ok=True)
        log_file = log_path / "scruxy.log"

        file_handler = RotatingFileHandler(
            str(log_file),
            maxBytes=1_000_000,  # 1 MB per file
            backupCount=9,       # 9 backups + 1 active = ~10 MB total
            encoding="utf-8",
        )
        file_handler.setFormatter(formatter)

        # Rename rotated files to include a datetime stamp.
        def _namer(default_name: str) -> str:
            stamp = _dt.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            return str(log_path / f"scruxy_{stamp}.log")

        file_handler.namer = _namer
        handlers.append(file_handler)

    logging.basicConfig(level=level, handlers=handlers)

    # Silence noisy loggers that clutter the output.
    logging.getLogger("asyncio").setLevel(logging.ERROR)   # SSL eof_received warning
    logging.getLogger("httpx").setLevel(logging.WARNING)   # per-request HTTP logs


def _register_signal_handlers() -> None:
    """No-op: uvicorn manages SIGINT/SIGTERM itself.

    Previous versions installed a handler that raised ``SystemExit(0)`` which
    conflicted with uvicorn's ``capture_signals`` context manager.  Uvicorn
    already performs graceful shutdown on SIGINT/SIGTERM, and the FastAPI
    lifespan shutdown block handles all cleanup (flushing sessions, stats, etc.).
    """


def _atexit_handler() -> None:
    """Last-resort cleanup on process exit."""
    logger.debug("atexit handler invoked")


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    """Build and return the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="scruxy",
        description="Scruxy — scrub PII from LLM API traffic",
    )
    parser.add_argument(
        "--config",
        type=str,
        default=None,
        help="Path to config YAML file (default: ~/.scruxy/config.yaml)",
    )
    parser.add_argument(
        "--mode",
        choices=["primary", "mitmproxy"],
        default=None,
        help="Interception mode override",
    )
    parser.add_argument(
        "--host",
        type=str,
        default=None,
        help="Listen host override (default: localhost)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="Listen port override (default: 8080)",
    )
    parser.add_argument(
        "--no-forward-proxy",
        action="store_true",
        default=False,
        help="Disable the HTTP forward proxy",
    )
    parser.add_argument(
        "--forward-proxy-port",
        type=int,
        default=None,
        help="Forward proxy listen port override (default: 8081)",
    )
    parser.add_argument(
        "--https-port",
        type=int,
        default=None,
        help="HTTPS reverse proxy listen port override (default: 8443)",
    )
    parser.add_argument(
        "--no-https",
        action="store_true",
        default=False,
        help="Disable the HTTPS reverse proxy listener",
    )
    parser.add_argument(
        "--no-browser",
        action="store_true",
        default=False,
        help="Don't open the control panel in a browser on startup",
    )
    return parser


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> None:
    """Parse arguments, build the app, print the banner, and start uvicorn."""
    parser = build_parser()
    args = parser.parse_args(argv)

    # 1. Load configuration ------------------------------------------------
    from scruxy.config.loader import load_config

    config_path = Path(args.config) if args.config else None
    config = load_config(path=config_path)

    # 2. Apply CLI overrides -----------------------------------------------
    if args.mode is not None:
        config.interception.mode = args.mode
    if args.host is not None:
        config.interception.listen_host = args.host
    if args.port is not None:
        config.interception.listen_port = args.port
    if args.no_forward_proxy:
        config.interception.forward_proxy.enabled = False
    if args.forward_proxy_port is not None:
        config.interception.forward_proxy.listen_port = args.forward_proxy_port
    if args.no_https:
        config.interception.https.enabled = False
    if args.https_port is not None:
        config.interception.https.listen_port = args.https_port

    # 3. Set up logging -----------------------------------------------------
    _configure_logging(config.logging.level, log_dir=config.logging.log_dir)

    # 4. Register signal + atexit handlers ----------------------------------
    _register_signal_handlers()
    atexit.register(_atexit_handler)

    # 5. Install mitmproxy cert if needed -----------------------------------
    if config.interception.mode == "mitmproxy":
        try:
            from scruxy.cert.manager import CertManager

            cert_mgr = CertManager(
                cert_dir=config.interception.mitmproxy.cert_dir,
                auto_uninstall_on_exit=config.interception.mitmproxy.auto_uninstall_cert_on_exit,
            )
            if cert_mgr.cert_exists() and not cert_mgr.is_cert_installed():
                if config.interception.mitmproxy.auto_install_cert:
                    logger.info("Installing mitmproxy CA certificate")
                    if not cert_mgr.install_cert():
                        logger.warning(
                            "Failed to install CA cert — HTTPS interception may not work. "
                            "Try running with admin/root privileges."
                        )
        except Exception:
            logger.exception("Error during mitmproxy cert setup")

    # 5b. Check / install Scruxy CA cert for forward proxy -------------------
    cert_status: dict | None = None
    if config.interception.forward_proxy.enabled:
        try:
            from scruxy.cert.ca import CertificateAuthority
            from scruxy.cert.manager import CertManager

            ca_cert_dir = Path(config.interception.forward_proxy.ca_cert_dir).expanduser()
            ca = CertificateAuthority(cert_dir=ca_cert_dir)

            scruxy_cert_mgr = CertManager(
                cert_dir=str(ca_cert_dir),
                auto_uninstall_on_exit=False,
                cert_path=ca.ca_cert_path,
                cert_cn="Scruxy PII Proxy CA",
            )
            cert_status = scruxy_cert_mgr.get_cert_info()
            logger.info(
                "Scruxy CA cert: exists=%s, installed=%s, expires=%s",
                cert_status["exists"],
                cert_status["installed"],
                cert_status.get("expiry_date", "unknown"),
            )

            if cert_status["exists"] and not cert_status["installed"]:
                if config.interception.forward_proxy.auto_install_ca_cert:
                    cleaned = scruxy_cert_mgr.cleanup_old_certs()
                    if cleaned:
                        logger.info("Removed %d stale CA cert(s) from trust store", cleaned)
                    logger.info("Installing Scruxy CA certificate into trust store")
                    if scruxy_cert_mgr.install_cert():
                        cert_status = scruxy_cert_mgr.get_cert_info()
                    else:
                        logger.warning(
                            "Failed to install Scruxy CA cert — forward proxy HTTPS "
                            "interception may not work. Try running with admin/root privileges."
                        )

            if cert_status.get("expiry_warning"):
                logger.warning(
                    "Scruxy CA cert expires in %d days (%s)",
                    cert_status["days_until_expiry"],
                    cert_status["expiry_date"],
                )
            if cert_status.get("expired"):
                logger.error(
                    "Scruxy CA cert has EXPIRED (%s) — regenerate it",
                    cert_status["expiry_date"],
                )

        except Exception:
            logger.exception("Error during Scruxy CA cert setup")

    # 6. Create the FastAPI app --------------------------------------------
    from scruxy.app import VERSION, create_app

    app = create_app(config, config_path=config_path)
    app.state._listen_host = config.interception.listen_host

    # Store cert status on app.state for dashboard API
    if cert_status is not None:
        app.state.cert_status = cert_status

    # 7. Print banner ------------------------------------------------------
    host = config.interception.listen_host
    port = config.interception.listen_port
    https_line = ""
    if config.interception.https.enabled:
        https_line = "\nHTTPS proxy:    https://{}:{}".format(host, config.interception.https.listen_port)
    if config.interception.forward_proxy.enabled:
        banner = _BANNER_TEMPLATE.format(
            version=VERSION,
            mode=config.interception.mode,
            host=host,
            port=port,
            https_line=https_line,
            fwd_port=config.interception.forward_proxy.listen_port,
        )
    else:
        banner = _BANNER_NO_FWD_TEMPLATE.format(
            version=VERSION,
            mode=config.interception.mode,
            host=host,
            port=port,
            https_line=https_line,
        )
    print(banner, flush=True)

    # 8. Open control panel in the default browser --------------------------
    if not args.no_browser:
        import threading
        import webbrowser

        ui_url = f"http://{host}:{port}/ui/"

        def _open_browser() -> None:
            try:
                webbrowser.open(ui_url)
            except Exception:
                pass

        # Delay slightly so uvicorn is accepting connections by the time
        # the browser makes its first request.
        threading.Timer(1.5, _open_browser).start()

    # 9. Start uvicorn -----------------------------------------------------
    import uvicorn

    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level=config.logging.level.lower(),
    )


if __name__ == "__main__":
    main()

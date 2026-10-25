"""TP3 - Breach the target (squelette).

Enchaîne une phase web (fuzzing + CAPTCHA) et une phase réseau (décodage
chronométré). Voir tp3-breach-the-target.md.

    poetry run tp3 --target http://127.0.0.1:8080
"""

import argparse

from tp3.utils.config import logger
from tp3.utils.session import Session


def breach_web(session: Session) -> str:
    """Fuzz les endpoints, casse le CAPTCHA, retourne (host, port, key).

    Affiche aussi Flag 1. Indices : requests, PIL, pytesseract.
    """
    flag1 = session.prepare_request()
    logger.info(f"FLAG_1: {flag1}")


def breach_network(session: Session) -> str:
    """pwntools/socket : décode le flux base64+XOR en boucle sous 30 s.

    Retourne le flag final. Indices : pwn.remote, base64.
    """
    logger.info("Starting network breach")
    session.submit_request()
    session.process_response()
    return session.get_flag()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="http://127.0.0.1:8080")
    args = ap.parse_args()

    logger.info("Starting TP3 - breach the target")
    session = Session(args.target)
    breach_web(session)
    flag = breach_network(session)
    logger.info(f"FLAG_FINAL: {flag}")


if __name__ == "__main__":
    main()

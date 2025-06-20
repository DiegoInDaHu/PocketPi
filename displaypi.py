#!/usr/bin/env python3
"""Launch Chromium in kiosk mode for PocketPi."""

import argparse
import shutil
import subprocess
import sys


def find_chromium():
    """Return path to Chromium executable or None if not found."""
    for candidate in ("chromium-browser", "chromium"):
        path = shutil.which(candidate)
        if path:
            return path
    return None


def main():
    parser = argparse.ArgumentParser(
        description="Abre una URL en Chromium en modo kiosco."\
    )
    parser.add_argument(
        "url",
        nargs="?",
        default="http://localhost",
        help="Direccion a mostrar (por defecto %(default)s)",
    )
    args = parser.parse_args()

    exe = find_chromium()
    if not exe:
        sys.stderr.write(
            "Error: no se encontro Chromium. Ejecuta install.sh para instalarlo.\n"
        )
        sys.exit(1)

    cmd = [
        exe,
        "--kiosk",
        "--noerrdialogs",
        "--disable-infobars",
        "--disable-translate",
        "--no-first-run",
        args.url,
    ]
    subprocess.call(cmd)


if __name__ == "__main__":
    main()

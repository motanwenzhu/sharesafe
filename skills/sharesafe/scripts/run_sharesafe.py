#!/usr/bin/env python3
"""Run the local ShareSafe CLI without installing or contacting anything."""

from __future__ import annotations

import sys
from collections.abc import Sequence
from typing import Callable


def _load_cli() -> Callable[[Sequence[str] | None], int | None]:
    """Import the bundled or already-installed ShareSafe entry point."""
    try:
        from sharesafe.cli import main as cli_main
    except ModuleNotFoundError as exc:
        if exc.name in {"sharesafe", "sharesafe.cli"}:
            raise RuntimeError(
                "ShareSafe CLI is unavailable. Keep the bundled scripts/sharesafe "
                "package beside this runner, or install the local ShareSafe package. "
                "This runner will not download or install dependencies."
            ) from exc
        raise
    return cli_main


def main(argv: Sequence[str] | None = None) -> int:
    """Forward arguments unchanged to ``sharesafe.cli.main``."""
    try:
        cli_main = _load_cli()
    except RuntimeError as exc:
        print(f"sharesafe runner error: {exc}", file=sys.stderr)
        return 4

    result = cli_main(list(sys.argv[1:] if argv is None else argv))
    return 0 if result is None else int(result)


if __name__ == "__main__":
    raise SystemExit(main())

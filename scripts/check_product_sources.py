"""Keep hand-written JavaScript out of the product source trees."""

from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
JAVASCRIPT_SUFFIXES = {".js", ".mjs", ".cjs", ".jsx"}


def main() -> None:
    listed = subprocess.check_output(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z", "--", "crates", "local/ui"],
        cwd=ROOT,
    )
    found = sorted(
        Path(name.decode())
        for name in listed.split(b"\0")
        if name and Path(name.decode()).suffix in JAVASCRIPT_SUFFIXES
    )
    if found:
        raise SystemExit("Product JavaScript must be TypeScript source:\n" + "\n".join(map(str, found)))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
import argparse
import json
from pathlib import Path


BEGIN_MARKER = "<!-- BEGIN:global_data_counts -->"
END_MARKER = "<!-- END:global_data_counts -->"


def render_counts(data_path: Path) -> str:
    payload = json.loads(data_path.read_text())
    return "\n".join(
        [
            BEGIN_MARKER,
            f"- `tokenlist`: {len(payload.get('tokenlist', []))} entries",
            f"- `pairs`: {len(payload.get('pairs', []))} entries",
            f"- `executor_abi`: {len(payload.get('executor_abi', []))} ABI items",
            END_MARKER,
        ]
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Sync README global_data counts from data/global_data.json"
    )
    parser.add_argument("--check", action="store_true", help="fail if README is out of date")
    parser.add_argument(
        "--readme",
        default="README.md",
        help="README file to update",
    )
    parser.add_argument(
        "--data",
        default="data/global_data.json",
        help="global data JSON to inspect",
    )
    args = parser.parse_args()

    readme_path = Path(args.readme)
    data_path = Path(args.data)
    readme = readme_path.read_text()
    rendered = render_counts(data_path)

    start = readme.find(BEGIN_MARKER)
    end = readme.find(END_MARKER)
    if start == -1 or end == -1 or end < start:
        raise SystemExit("README markers for global_data counts are missing")
    end += len(END_MARKER)
    updated = readme[:start] + rendered + readme[end:]

    if args.check:
        if updated != readme:
            raise SystemExit("README global_data counts are out of date")
        return 0

    if updated != readme:
        readme_path.write_text(updated)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

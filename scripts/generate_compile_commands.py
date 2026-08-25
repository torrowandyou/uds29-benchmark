#!/usr/bin/env python3
"""Generate one clang compilation database for the benchmark and Tongsuo."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile


SOURCE_SUFFIXES = {".c", ".cc", ".cpp", ".cxx", ".C"}
COMPILER_NAMES = {"cc", "clang", "gcc"}


def resolve_compiler(command: str) -> str:
    words = shlex.split(command)
    if len(words) != 1:
        raise SystemExit(f"CC must name one compiler executable, got: {command!r}")
    return shutil.which(words[0]) or words[0]


def benchmark_entries(root: Path, prefix: Path, compiler: str) -> list[dict[str, object]]:
    common = [
        compiler,
        f"-I{prefix.resolve() / 'include'}",
        f"-I{root.resolve() / 'src'}",
        "-O2",
        "-g",
        "-std=c11",
        "-Wall",
        "-Wextra",
        "-Wpedantic",
        "-Wno-deprecated-declarations",
    ]
    sources = ["src/uds29_bench.c", "src/gmt0130.c", "tests/gmt0130_test.c"]
    return [
        {
            "directory": str(root.resolve()),
            "file": str((root / source).resolve()),
            "arguments": common + ["-c", str((root / source).resolve())],
        }
        for source in sources
    ]


def source_argument(arguments: list[str], build_dir: Path) -> Path | None:
    try:
        compile_index = arguments.index("-c")
    except ValueError:
        return None

    candidates = arguments[compile_index + 1 :] + arguments[:compile_index]
    for argument in reversed(candidates):
        if argument.startswith("-") or Path(argument).suffix not in SOURCE_SUFFIXES:
            continue
        source = Path(argument)
        if not source.is_absolute():
            source = build_dir / source
        source = source.resolve()
        if source.is_file():
            return source
    return None


def tongsuo_entries(build_dir: Path, source_dir: Path) -> list[dict[str, object]]:
    if not (build_dir / "Makefile").is_file():
        raise SystemExit(
            f"Tongsuo build Makefile not found: {build_dir / 'Makefile'}\n"
            "Run ./run_benchmark.sh once to configure and build local Tongsuo."
        )

    command = [
        "make",
        "-C",
        str(build_dir),
        "-Bn",
        "-o",
        "Makefile",
        "-o",
        "Makefile.in",
        "-o",
        "configdata.pm",
        "_build_libs",
    ]
    result = subprocess.run(command, text=True, capture_output=True, check=False)
    if result.returncode != 0:
        sys.stderr.write(result.stderr)
        raise SystemExit(f"Failed to expand Tongsuo compile commands ({result.returncode})")

    source_dir = source_dir.resolve()
    entries: dict[Path, dict[str, object]] = {}
    for line in result.stdout.splitlines():
        try:
            arguments = shlex.split(line)
        except ValueError:
            continue
        if not arguments or Path(arguments[0]).name not in COMPILER_NAMES:
            continue
        source = source_argument(arguments, build_dir)
        if source is None:
            continue
        try:
            source.relative_to(source_dir)
        except ValueError:
            # Generated build-tree sources do not help navigation in Tongsuo.
            continue
        arguments[0] = shutil.which(arguments[0]) or arguments[0]
        entries.setdefault(
            source,
            {
                "directory": str(build_dir),
                "file": str(source),
                "arguments": arguments,
            },
        )
    if not entries:
        raise SystemExit("No Tongsuo C compile commands were found")
    return list(entries.values())


def main() -> None:
    root = Path(__file__).resolve().parent.parent
    workspace = root.parent
    tongsuo_source = Path(os.environ.get("TONGSUO_SOURCE", workspace / "Tongsuo"))
    tongsuo_build = Path(
        os.environ.get("TONGSUO_BUILD", root / "build/tongsuo-build")
    )
    tongsuo_prefix = Path(
        os.environ.get("TONGSUO_PREFIX", root / "build/tongsuo-install")
    )
    compiler = resolve_compiler(os.environ.get("CC", "cc"))

    entries = benchmark_entries(root, tongsuo_prefix, compiler)
    entries.extend(tongsuo_entries(tongsuo_build.resolve(), tongsuo_source.resolve()))
    entries.sort(key=lambda entry: str(entry["file"]))

    output = workspace / "compile_commands.json"
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=workspace, prefix=".compile_commands.", delete=False
    ) as temporary:
        json.dump(entries, temporary, indent=2)
        temporary.write("\n")
        temporary_name = temporary.name
    os.replace(temporary_name, output)
    output.chmod(0o644)
    print(f"Generated {output} with {len(entries)} translation units")


if __name__ == "__main__":
    main()

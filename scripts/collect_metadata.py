#!/usr/bin/env python3
"""Collect reproducibility metadata for a benchmark run."""

from __future__ import annotations

import argparse
import datetime as dt
import getpass
import json
import os
import platform
import re
import shutil
import shlex
import socket
import subprocess
from pathlib import Path


def command_output(command, *, env=None, timeout=15):
    try:
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            env=env,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    output = result.stdout.strip()
    return output if result.returncode == 0 and output else None


def read_text(path):
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace").strip().strip(chr(0))
    except OSError:
        return None


def read_int(path):
    value = read_text(path)
    try:
        return int(value) if value is not None else None
    except ValueError:
        return None


def git_info(path):
    path = Path(path)
    if not (path / ".git").exists():
        return {"available": False}
    commit = command_output(["git", "-C", str(path), "rev-parse", "HEAD"])
    status = command_output(["git", "-C", str(path), "status", "--porcelain"])
    return {
        "available": True,
        "commit": commit,
        "worktree": "dirty" if status else "clean",
    }


def parse_os_release():
    result = {}
    path = Path("/etc/os-release")
    if not path.exists():
        return result
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if "=" not in line or line.startswith("#"):
            continue
        key, value = line.split("=", 1)
        result[key.lower()] = value.strip().strip("'").strip('"')
    return result


def parse_lscpu():
    output = command_output(["lscpu", "--json"])
    entries = {}
    if output:
        try:
            for item in json.loads(output).get("lscpu", []):
                field = str(item.get("field", "")).rstrip(":")
                entries[field] = item.get("data")
            return entries
        except (json.JSONDecodeError, TypeError):
            pass
    output = command_output(["lscpu"])
    if output:
        for line in output.splitlines():
            if ":" in line:
                key, value = line.split(":", 1)
                entries[key.strip()] = value.strip()
    return entries


def parse_memory_modules():
    if not shutil.which("dmidecode"):
        return [], "dmidecode not installed"
    output = command_output(["dmidecode", "--type", "memory"])
    if not output:
        return [], "permission denied or unavailable"
    wanted = {
        "Locator",
        "Bank Locator",
        "Size",
        "Type",
        "Speed",
        "Configured Memory Speed",
        "Manufacturer",
        "Part Number",
        "Rank",
    }
    modules = []
    current = None
    for line in output.splitlines():
        if line.strip() == "Memory Device":
            if current and current.get("Size") != "No Module Installed":
                modules.append(current)
            current = {}
            continue
        if current is None or ":" not in line:
            continue
        key, value = (part.strip() for part in line.split(":", 1))
        if key in wanted:
            current[key] = value
    if current and current.get("Size") != "No Module Installed":
        modules.append(current)
    return modules, "ok"


def linux_cpu_frequency():
    root = Path("/sys/devices/system/cpu")
    current = []
    governors = set()
    drivers = set()
    for cpu_dir in sorted(root.glob("cpu[0-9]*")):
        cpufreq = cpu_dir / "cpufreq"
        value = read_int(cpufreq / "scaling_cur_freq")
        if value is not None:
            current.append(value)
        governor = read_text(cpufreq / "scaling_governor")
        driver = read_text(cpufreq / "scaling_driver")
        if governor:
            governors.add(governor)
        if driver:
            drivers.add(driver)
    frequency = {
        "min_khz": read_int(root / "cpu0/cpufreq/cpuinfo_min_freq"),
        "max_khz": read_int(root / "cpu0/cpufreq/cpuinfo_max_freq"),
        "current_khz": {
            "minimum": min(current) if current else None,
            "maximum": max(current) if current else None,
            "average": round(sum(current) / len(current)) if current else None,
            "sampled_cpus": len(current),
        },
        "governors": sorted(governors),
        "drivers": sorted(drivers),
    }
    boost = read_text(root / "cpufreq/boost")
    no_turbo = read_text(root / "intel_pstate/no_turbo")
    if boost is not None:
        frequency["boost_enabled"] = boost == "1"
    elif no_turbo is not None:
        frequency["boost_enabled"] = no_turbo == "0"
    else:
        frequency["boost_enabled"] = None
    return frequency


def linux_metadata():
    lscpu = parse_lscpu()
    modules, module_status = parse_memory_modules()
    mem_total_kb = None
    meminfo = read_text("/proc/meminfo")
    if meminfo:
        match = re.search(r"^MemTotal:\s+(\d+)\s+kB", meminfo, re.MULTILINE)
        if match:
            mem_total_kb = int(match.group(1))
    virtualization = command_output(["systemd-detect-virt"]) if shutil.which("systemd-detect-virt") else None
    hardware = {
        "system_vendor": read_text("/sys/devices/virtual/dmi/id/sys_vendor"),
        "product_name": read_text("/sys/devices/virtual/dmi/id/product_name"),
        "product_version": read_text("/sys/devices/virtual/dmi/id/product_version"),
        "board_name": read_text("/sys/devices/virtual/dmi/id/board_name"),
        "device_tree_model": read_text("/proc/device-tree/model"),
    }
    cpu_model = lscpu.get("Model name")
    if not cpu_model or cpu_model == "-":
        cpuinfo = read_text("/proc/cpuinfo") or ""
        for key in ("model name", "Hardware", "Processor", "cpu model"):
            match = re.search(rf"^{re.escape(key)}\s*:\s*(.+)$", cpuinfo, re.MULTILINE | re.IGNORECASE)
            if match and not match.group(1).strip().isdigit():
                cpu_model = match.group(1).strip()
                break
        else:
            cpu_model = platform.processor() or None
    cpu = {
        "architecture": lscpu.get("Architecture") or platform.machine(),
        "model_name": cpu_model,
        "vendor_id": lscpu.get("Vendor ID"),
        "sockets": lscpu.get("Socket(s)"),
        "cores_per_socket": lscpu.get("Core(s) per socket"),
        "threads_per_core": lscpu.get("Thread(s) per core"),
        "logical_cpus": lscpu.get("CPU(s)") or os.cpu_count(),
        "numa_nodes": lscpu.get("NUMA node(s)"),
        "byte_order": lscpu.get("Byte Order"),
        "flags": (lscpu.get("Flags") or lscpu.get("Features") or "").split(),
        "frequency": {
            **linux_cpu_frequency(),
            "lscpu_min_mhz": lscpu.get("CPU min MHz"),
            "lscpu_max_mhz": lscpu.get("CPU max MHz"),
            "note": "Current frequency is a point-in-time sample and may change under DVFS.",
        },
        "lscpu": lscpu,
    }
    return {
        "distribution": parse_os_release(),
        "virtualization": virtualization or "none detected",
        "hardware": hardware,
        "cpu": cpu,
        "memory": {
            "total_bytes": mem_total_kb * 1024 if mem_total_kb is not None else None,
            "modules": modules,
            "module_query_status": module_status,
        },
    }


def sysctl_value(name):
    return command_output(["sysctl", "-n", name])


def macos_metadata():
    hardware_output = command_output(["system_profiler", "SPHardwareDataType", "SPMemoryDataType", "-json"], timeout=30)
    try:
        profiler = json.loads(hardware_output) if hardware_output else None
    except json.JSONDecodeError:
        profiler = None
    return {
        "distribution": {
            "product_name": command_output(["sw_vers", "-productName"]),
            "product_version": command_output(["sw_vers", "-productVersion"]),
            "build_version": command_output(["sw_vers", "-buildVersion"]),
        },
        "virtualization": "unavailable",
        "hardware": {
            "model": sysctl_value("hw.model"),
            "system_profiler": profiler,
        },
        "cpu": {
            "architecture": platform.machine(),
            "model_name": sysctl_value("machdep.cpu.brand_string") or sysctl_value("hw.model"),
            "physical_cores": sysctl_value("hw.physicalcpu"),
            "logical_cpus": sysctl_value("hw.logicalcpu"),
            "frequency_hz": sysctl_value("hw.cpufrequency"),
            "frequency_max_hz": sysctl_value("hw.cpufrequency_max"),
            "frequency_min_hz": sysctl_value("hw.cpufrequency_min"),
        },
        "memory": {
            "total_bytes": int(sysctl_value("hw.memsize")) if (sysctl_value("hw.memsize") or "").isdigit() else None,
            "system_profiler_included": profiler is not None,
        },
    }


def linked_libraries(binary):
    if platform.system() == "Darwin":
        output = command_output(["otool", "-L", str(binary)])
    else:
        output = command_output(["ldd", str(binary)])
    return output.splitlines() if output else []


def tongsuo_metadata(prefix, source):
    prefix = Path(prefix)
    executable = prefix / "bin/openssl"
    library_path = f"{prefix / 'lib64'}:{prefix / 'lib'}"
    env = os.environ.copy()
    env["LD_LIBRARY_PATH"] = library_path + (":" + env["LD_LIBRARY_PATH"] if env.get("LD_LIBRARY_PATH") else "")
    env["DYLD_LIBRARY_PATH"] = library_path + (":" + env["DYLD_LIBRARY_PATH"] if env.get("DYLD_LIBRARY_PATH") else "")
    version = command_output([str(executable), "version", "-a"], env=env) if executable.exists() else None
    return {
        "prefix": str(prefix),
        "version": version.splitlines() if version else [],
        "source": git_info(source),
    }


def compiler_metadata(compiler):
    command = shlex.split(compiler)
    version = command_output([*command, "--version"]) if command else None
    return {
        "command": compiler,
        "version": version.splitlines() if version else [],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--device-id", required=True)
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--tongsuo-prefix", required=True, type=Path)
    parser.add_argument("--tongsuo-source", required=True, type=Path)
    parser.add_argument("--compiler", default="cc")
    parser.add_argument("--iterations", required=True, type=int)
    parser.add_argument("--warmup", required=True, type=int)
    parser.add_argument("--cpu-affinity", default="unbound")
    args = parser.parse_args()

    system = platform.system()
    platform_details = linux_metadata() if system == "Linux" else macos_metadata() if system == "Darwin" else {
        "distribution": {},
        "virtualization": "unavailable",
        "hardware": {},
        "cpu": {"architecture": platform.machine(), "logical_cpus": os.cpu_count()},
        "memory": {"total_bytes": None},
    }

    libc_name, libc_version = platform.libc_ver()
    make_dry_run = command_output([
        "make",
        "-C",
        str(args.repo_root),
        "-n",
        "-B",
        f"TONGSUO_PREFIX={args.tongsuo_prefix}",
        f"CC={args.compiler}",
        "build/uds29_bench",
    ])
    try:
        load_average = list(os.getloadavg())
    except OSError:
        load_average = None
    metadata = {
        "schema_version": 1,
        "generated_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "device": {
            "id": args.device_id,
            "user": getpass.getuser(),
            "hostname": socket.gethostname(),
        },
        "operating_system": {
            "system": system,
            "release": platform.release(),
            "version": platform.version(),
            "kernel": command_output(["uname", "-a"]),
            "distribution": platform_details["distribution"],
            "virtualization": platform_details["virtualization"],
        },
        "hardware": platform_details["hardware"],
        "cpu": platform_details["cpu"],
        "memory": platform_details["memory"],
        "benchmark": {
            "source": git_info(args.repo_root),
            "iterations": args.iterations,
            "warmup": args.warmup,
            "cpu_affinity": args.cpu_affinity,
            "executable": str(args.binary),
            "linked_libraries": linked_libraries(args.binary),
            "system_load_average": load_average,
        },
        "build": {
            "compiler": compiler_metadata(args.compiler),
            "effective_make_dry_run": make_dry_run.splitlines() if make_dry_run else [],
            "environment": {
                name: os.environ.get(name)
                for name in ("CC", "CFLAGS", "CPPFLAGS", "LDFLAGS", "JOBS")
            },
        },
        "dependencies": {
            "tongsuo": tongsuo_metadata(args.tongsuo_prefix, args.tongsuo_source),
            "libc": {"name": libc_name or None, "version": libc_version or None},
            "python": platform.python_version(),
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(metadata, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Generated {args.output}")


if __name__ == "__main__":
    main()

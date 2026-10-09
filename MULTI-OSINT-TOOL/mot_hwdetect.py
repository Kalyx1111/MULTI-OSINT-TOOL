"""MULTI-OSINT-TOOL :: hardware detection and auto-tuning (CPU / RAM / GPU / OS)."""
from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys


def _ram_gb() -> float:
    try:
        import psutil

        return round(psutil.virtual_memory().total / 2**30, 1)
    except Exception:
        pass
    try:
        if sys.platform.startswith("linux"):
            with open("/proc/meminfo") as fh:
                for line in fh:
                    if line.startswith("MemTotal:"):
                        return round(int(line.split()[1]) / 2**20, 1)
        if sys.platform == "darwin":
            out = subprocess.run(["sysctl", "-n", "hw.memsize"], capture_output=True, text=True, timeout=3).stdout
            return round(int(out.strip()) / 2**30, 1)
        if os.name == "nt":
            import ctypes

            class MS(ctypes.Structure):
                _fields_ = [("l", ctypes.c_ulong), ("m", ctypes.c_ulong)] + [(f"x{i}", ctypes.c_ulonglong) for i in range(7)]

            ms = MS()
            ms.l = ctypes.sizeof(MS)
            ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(ms))
            return round(ms.x0 / 2**30, 1)
    except Exception:
        pass
    return 4.0


def _gpu() -> dict:
    exe = shutil.which("nvidia-smi")
    if not exe:
        return {"name": "", "vram_gb": 0.0}
    try:
        out = subprocess.run(
            [exe, "--query-gpu=name,memory.total", "--format=csv,noheader,nounits"],
            capture_output=True, text=True, timeout=4, check=False,
        ).stdout.strip().splitlines()[0]
        name, mem = [x.strip() for x in out.split(",")[:2]]
        return {"name": name, "vram_gb": round(int(mem) / 1024, 1)}
    except Exception:
        return {"name": "", "vram_gb": 0.0}


def detect() -> dict:
    return {
        "os": f"{platform.system()} {platform.release()}",
        "machine": platform.machine(),
        "python": platform.python_version(),
        "cpu_cores": os.cpu_count() or 1,
        "ram_gb": _ram_gb(),
        "gpu": _gpu(),
    }


def suggest_local_llm(hw: dict) -> str:
    """Advisory only (roadmap: local-only AI summariser). Picks a quantisation from VRAM, else RAM."""
    vram, ram = hw.get("gpu", {}).get("vram_gb", 0.0), hw["ram_gb"]
    if vram >= 24:
        return "13-14B at Q8_0 or 30B at Q4_K_M"
    if vram >= 12:
        return "13B at Q5_K_M"
    if vram >= 8:
        return "7-8B at Q5_K_M"
    if vram >= 4:
        return "3-4B at Q4_K_M"
    if ram >= 16:
        return "7-8B at Q4_K_M (CPU, slow)"
    return "1-3B at Q4_K_M (CPU) or skip local AI"


def autotune(hw: dict | None = None) -> dict:
    hw = hw or detect()
    cores, ram = hw["cpu_cores"], hw["ram_gb"]
    workers = max(4, min(16, cores * 2))
    if ram < 4:
        workers = min(workers, 6)
    cli_parallel = 1 if ram < 4 else 2 if ram < 8 else 3
    from mot_vault import default_kdf

    return {"max_workers": workers, "cli_parallel": cli_parallel, "kdf": default_kdf(ram, cores), "local_llm": suggest_local_llm(hw)}

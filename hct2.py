#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════╗
║   FORENSIC FILE HASHER  — Production Grade  v1.0        ║
║   Deep static fingerprinting with enterprise logging     ║
╚══════════════════════════════════════════════════════════╝

Architecture:
  [logger]      → Structured logging with correlation IDs
  [deps]        → Auto-install / graceful degradation
  [hashing]     → MD5, SHA*, CRC32, BLAKE2, SHA3
  [fuzzy]       → ssdeep, TLSH
  [pe_analysis] → imphash, section hashing, entropy, signature
  [reporter]    → Console + JSON output, timing metrics
  [main]        → CLI entry-point
"""

# ─────────────────────────────────────────────
#  SECTION 0 ─ STDLIB BOOTSTRAP (always safe)
# ─────────────────────────────────────────────
import argparse
import hashlib
import importlib
import json
import logging
import math
import mimetypes
import os
import platform
import subprocess
import sys
import time
import uuid
import zlib
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

# ─────────────────────────────────────────────
#  SECTION 1 ─ LOGGER MODULE
# ─────────────────────────────────────────────

_RUN_ID = str(uuid.uuid4())[:8]   # Correlation ID for this run


def _build_logger(name: str = "forensic_hasher",
                  log_file: str = "analysis.log",
                  verbose: bool = False) -> logging.Logger:
    """
    Returns a configured logger that writes to both console and file.
    Format:  TIMESTAMP [LEVEL] [run:<id>] [func] message
    """
    logger = logging.getLogger(name)
    if logger.handlers:          # idempotent — don't add duplicate handlers
        return logger

    level = logging.DEBUG if verbose else logging.INFO
    logger.setLevel(logging.DEBUG)   # capture everything; handlers filter

    fmt = logging.Formatter(
        fmt="%(asctime)s [%(levelname)-8s] [run:%(run_id)s] [%(func_name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    class _CtxFilter(logging.Filter):
        """Inject run_id + func_name into every record."""
        def filter(self, record: logging.LogRecord) -> bool:
            record.run_id = _RUN_ID
            if not hasattr(record, "func_name"):
                record.func_name = record.funcName
            return True

    filt = _CtxFilter()

    # Console handler
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(level)
    ch.setFormatter(fmt)
    ch.addFilter(filt)
    logger.addHandler(ch)

    # File handler
    try:
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setLevel(logging.DEBUG)   # always full detail in file
        fh.setFormatter(fmt)
        fh.addFilter(filt)
        logger.addHandler(fh)
    except OSError as exc:
        logger.warning(f"Cannot open log file '{log_file}': {exc}. File logging disabled.")

    return logger


# Module-level logger (reconfigured in main() once CLI args are parsed)
log = _build_logger()


def _log(level: str, func: str, msg: str) -> None:
    """Helper: emit a log record with an explicit func_name override."""
    record = logging.LogRecord(
        name=log.name, level=getattr(logging, level.upper()),
        pathname="", lineno=0, msg=msg, args=(), exc_info=None
    )
    record.func_name = func
    record.run_id = _RUN_ID
    log.handle(record)


# ─────────────────────────────────────────────
#  SECTION 2 ─ DEPENDENCY MANAGER
# ─────────────────────────────────────────────

_OPTIONAL_DEPS: Dict[str, str] = {
    # import_name : pip_package
    "ppdeep":    "ppdeep",
    "ssdeep":    "ssdeep",
    "tlsh":      "python-tlsh",
    "pefile":    "pefile",
    "magic":     "python-magic",
    "colorama":  "colorama",
}


def _try_install(pip_name: str) -> bool:
    """Attempt pip install; return True on success."""
    _log("INFO", "dep_manager", f"Auto-installing: {pip_name}")
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", pip_name, "--quiet"],
            capture_output=True, text=True, timeout=120
        )
        if result.returncode == 0:
            _log("INFO", "dep_manager", f"Installed {pip_name} successfully.")
            return True
        else:
            _log("ERROR", "dep_manager",
                 f"pip failed for {pip_name}.\n"
                 f"  stdout: {result.stdout.strip()}\n"
                 f"  stderr: {result.stderr.strip()}\n"
                 f"  Hint: try manually → pip install {pip_name}")
            return False
    except subprocess.TimeoutExpired:
        _log("ERROR", "dep_manager", f"pip install timed out for {pip_name}.")
        return False
    except Exception as exc:
        _log("ERROR", "dep_manager", f"Unexpected error installing {pip_name}: {exc}")
        return False


def _import_optional(import_name: str) -> Optional[Any]:
    """
    Try to import a module; auto-install once if missing.
    Returns the module or None.
    """
    try:
        mod = importlib.import_module(import_name)
        _log("DEBUG", "dep_manager", f"Import OK: {import_name}")
        return mod
    except ImportError:
        pip_name = _OPTIONAL_DEPS.get(import_name, import_name)
        _log("WARNING", "dep_manager",
             f"Module '{import_name}' not found. Attempting install of '{pip_name}'…")
        if _try_install(pip_name):
            try:
                mod = importlib.import_module(import_name)
                return mod
            except ImportError as exc:
                _log("ERROR", "dep_manager",
                     f"Import still failed after install: {exc}\n"
                     f"  Manual fix: pip install {pip_name}")
        return None


# Load optional modules once at startup
_colorama = _import_optional("colorama")
_pefile   = _import_optional("pefile")
_magic    = _import_optional("magic")

# ssdeep: try ppdeep first (pure-Python, no C build needed), then ssdeep
_ssdeep_mod  = None
_ssdeep_lib  = None
_ppdeep      = _import_optional("ppdeep")
if _ppdeep:
    _ssdeep_mod, _ssdeep_lib = _ppdeep, "ppdeep"
else:
    _ssdeep_raw = _import_optional("ssdeep")
    if _ssdeep_raw:
        _ssdeep_mod, _ssdeep_lib = _ssdeep_raw, "ssdeep"

_tlsh_mod = _import_optional("tlsh")

# Colorama init
if _colorama:
    _colorama.init(autoreset=True)
    C = _colorama.Fore
    S = _colorama.Style
else:
    class _Dummy:
        def __getattr__(self, _): return ""
    C = S = _Dummy()


# ─────────────────────────────────────────────
#  SECTION 3 ─ HASHING MODULE
# ─────────────────────────────────────────────

CHUNK_SIZE = 65_536   # 64 KB


def _stream_file(path: Path) -> Tuple[Optional[bytes], Optional[str]]:
    """
    Read file in streaming chunks.
    Returns (full_bytes_or_None_if_large, error_msg_or_None).
    For files > 512 MB we only stream (no full buffer).
    """
    MAX_BUFFER = 512 * 1024 * 1024   # 512 MB
    _log("DEBUG", "_stream_file", f"Opening '{path}' for streaming read.")
    chunks = []
    total = 0
    try:
        with open(path, "rb") as fh:
            while True:
                chunk = fh.read(CHUNK_SIZE)
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > MAX_BUFFER:
                    # Drain rest without storing
                    while fh.read(CHUNK_SIZE):
                        pass
                    _log("WARNING", "_stream_file",
                         f"File > {MAX_BUFFER // 1_048_576} MB — fuzzy hashes will be skipped.")
                    return None, "FILE_TOO_LARGE"
        data = b"".join(chunks)
        _log("DEBUG", "_stream_file", f"Read {total:,} bytes OK.")
        return data, None
    except PermissionError:
        return None, "PERMISSION_DENIED"
    except OSError as exc:
        return None, f"OS_ERROR: {exc}"


def compute_standard_hashes(data: bytes) -> Dict[str, Any]:
    """
    Compute MD5, SHA1, SHA224, SHA256, SHA384, SHA512,
    SHA3-256, SHA3-512, BLAKE2b, BLAKE2s, CRC32.
    Each hash is individually try/caught.
    """
    fn = "compute_standard_hashes"
    _log("INFO", fn, f"Computing standard hashes on {len(data):,} bytes.")
    results = {}
    t0 = time.perf_counter()

    algos = [
        "md5", "sha1", "sha224", "sha256", "sha384", "sha512",
        "sha3_256", "sha3_512", "blake2b", "blake2s"
    ]

    for algo in algos:
        t_a = time.perf_counter()
        try:
            h = hashlib.new(algo, data)
            results[algo.upper()] = {
                "value": h.hexdigest(),
                "status": "ok",
                "time_ms": round((time.perf_counter() - t_a) * 1000, 2)
            }
            _log("DEBUG", fn, f"{algo.upper()} = {h.hexdigest()[:16]}…")
        except Exception as exc:
            msg = f"hashlib.new('{algo}') failed: {exc}"
            _log("ERROR", fn, msg)
            results[algo.upper()] = {
                "value": None, "status": "error",
                "error": msg,
                "hint": "Algorithm may not be supported on this Python build.",
                "time_ms": round((time.perf_counter() - t_a) * 1000, 2)
            }

    # CRC32 (separate, not in hashlib)
    t_a = time.perf_counter()
    try:
        crc = zlib.crc32(data) & 0xFFFFFFFF
        results["CRC32"] = {
            "value": f"{crc:08x}",
            "status": "ok",
            "time_ms": round((time.perf_counter() - t_a) * 1000, 2)
        }
        _log("DEBUG", fn, f"CRC32 = {results['CRC32']['value']}")
    except Exception as exc:
        msg = f"CRC32 computation failed: {exc}"
        _log("ERROR", fn, msg)
        results["CRC32"] = {"value": None, "status": "error", "error": msg,
                             "time_ms": round((time.perf_counter() - t_a) * 1000, 2)}

    elapsed = round((time.perf_counter() - t0) * 1000, 2)
    _log("INFO", fn, f"Standard hashes complete in {elapsed} ms.")
    return results


# ─────────────────────────────────────────────
#  SECTION 4 ─ FUZZY HASHING MODULE
# ─────────────────────────────────────────────

MIN_SSDEEP_BYTES = 4096    # ssdeep needs some data to be meaningful
MIN_TLSH_BYTES   = 50      # TLSH hard minimum


def compute_ssdeep(data: bytes) -> Dict[str, Any]:
    fn = "compute_ssdeep"
    _log("INFO", fn, f"ssdeep requested. lib={_ssdeep_lib or 'none'}, data={len(data):,} bytes.")
    t0 = time.perf_counter()

    if _ssdeep_mod is None:
        msg = "ssdeep/ppdeep module not available."
        _log("WARNING", fn, msg)
        return {"value": None, "status": "unavailable",
                "error": msg,
                "hint": "Install with: pip install ppdeep   (pure-Python) or pip install ssdeep (needs C libs)"}

    if len(data) < MIN_SSDEEP_BYTES:
        msg = f"File too small ({len(data)} bytes < {MIN_SSDEEP_BYTES} bytes minimum)."
        _log("WARNING", fn, msg)
        return {"value": None, "status": "skipped",
                "error": msg,
                "hint": "Expected limitation — ssdeep requires substantial data to produce a meaningful hash.",
                "time_ms": 0}

    try:
        if _ssdeep_lib == "ppdeep":
            val = _ssdeep_mod.hash(data)
        else:
            h = _ssdeep_mod.Hash()
            h.update(data)
            val = h.digest()
        elapsed = round((time.perf_counter() - t0) * 1000, 2)
        _log("INFO", fn, f"ssdeep OK in {elapsed} ms: {val[:40]}…")
        return {"value": val, "status": "ok", "time_ms": elapsed}
    except Exception as exc:
        msg = f"ssdeep computation error: {type(exc).__name__}: {exc}"
        _log("ERROR", fn, msg)
        return {"value": None, "status": "error", "error": msg,
                "hint": "May indicate a corrupt/unusual file or library version incompatibility.",
                "time_ms": round((time.perf_counter() - t0) * 1000, 2)}


def compute_tlsh(data: bytes) -> Dict[str, Any]:
    fn = "compute_tlsh"
    _log("INFO", fn, f"TLSH requested. lib={'tlsh' if _tlsh_mod else 'none'}, data={len(data):,} bytes.")
    t0 = time.perf_counter()

    if _tlsh_mod is None:
        msg = "tlsh module not available."
        _log("WARNING", fn, msg)
        return {"value": None, "status": "unavailable",
                "error": msg,
                "hint": "Install with: pip install python-tlsh"}

    if len(data) < MIN_TLSH_BYTES:
        msg = (f"File too small for TLSH ({len(data)} bytes < {MIN_TLSH_BYTES} bytes minimum).\n"
               f"  Error Type   : ValueError (logical)\n"
               f"  Operation    : TLSH Hashing\n"
               f"  Root Cause   : not enough data for TLSH\n"
               f"  Suggested    : Expected limitation for very small files or empty files.")
        _log("WARNING", fn, msg)
        return {"value": None, "status": "skipped", "error": msg,
                "hint": "Expected limitation — TLSH needs >= 50 bytes of data.",
                "time_ms": 0}

    # Universal wrapper: try all known TLSH API variants
    errors = []

    # Variant 1: tlsh.hash(bytes)
    try:
        val = _tlsh_mod.hash(data)
        elapsed = round((time.perf_counter() - t0) * 1000, 2)
        _log("INFO", fn, f"TLSH (v1) OK in {elapsed} ms.")
        return {"value": val, "status": "ok", "time_ms": elapsed}
    except Exception as exc:
        errors.append(f"v1 (hash): {exc}")

    # Variant 2: Tlsh class
    try:
        t = _tlsh_mod.Tlsh()
        t.update(data)
        t.final()
        val = t.hexdigest()
        elapsed = round((time.perf_counter() - t0) * 1000, 2)
        _log("INFO", fn, f"TLSH (v2/class) OK in {elapsed} ms.")
        return {"value": val, "status": "ok", "time_ms": elapsed}
    except Exception as exc:
        errors.append(f"v2 (Tlsh class): {exc}")

    # Variant 3: forcehash
    try:
        val = _tlsh_mod.forcehash(data)
        elapsed = round((time.perf_counter() - t0) * 1000, 2)
        _log("INFO", fn, f"TLSH (v3/forcehash) OK in {elapsed} ms.")
        return {"value": val, "status": "ok", "time_ms": elapsed}
    except Exception as exc:
        errors.append(f"v3 (forcehash): {exc}")

    combined = " | ".join(errors)
    msg = (f"All TLSH API variants failed.\n"
           f"  Error Type   : LibraryIncompatibility\n"
           f"  Operation    : TLSH Hashing\n"
           f"  Root Cause   : {combined}\n"
           f"  Suggested    : Try reinstalling: pip install python-tlsh --force-reinstall")
    _log("ERROR", fn, msg)
    return {"value": None, "status": "error", "error": combined,
            "hint": "Library version mismatch. Reinstall python-tlsh.",
            "time_ms": round((time.perf_counter() - t0) * 1000, 2)}


# ─────────────────────────────────────────────
#  SECTION 5 ─ PE ANALYSIS MODULE
# ─────────────────────────────────────────────

def _is_pe_file(data: bytes) -> bool:
    return len(data) >= 2 and data[:2] == b"MZ"


def compute_imphash(path: Path) -> Dict[str, Any]:
    fn = "compute_imphash"
    _log("INFO", fn, f"imphash for: {path.name}")
    t0 = time.perf_counter()

    if _pefile is None:
        msg = "pefile module not available."
        _log("WARNING", fn, msg)
        return {"value": None, "status": "unavailable",
                "error": msg, "hint": "Install with: pip install pefile"}
    try:
        pe = _pefile.PE(str(path), fast_load=True)
        pe.parse_data_directories()
        ih = pe.get_imphash()
        pe.close()
        elapsed = round((time.perf_counter() - t0) * 1000, 2)
        _log("INFO", fn, f"imphash = {ih} ({elapsed} ms)")
        return {"value": ih or "(no imports)", "status": "ok", "time_ms": elapsed}
    except _pefile.PEFormatError:
        msg = (f"Not a valid PE/MZ file.\n"
               f"  Error Type   : PEFormatError\n"
               f"  Operation    : PE Parsing\n"
               f"  Root Cause   : File does not start with valid PE header\n"
               f"  Suggested    : Expected for non-PE files (scripts, docs, etc.)")
        _log("WARNING", fn, msg)
        return {"value": None, "status": "skipped", "error": msg,
                "hint": "Expected — file is not a Windows PE executable.",
                "time_ms": round((time.perf_counter() - t0) * 1000, 2)}
    except Exception as exc:
        msg = (f"PE parsing failed: {type(exc).__name__}: {exc}\n"
               f"  Suggested    : File may be corrupted, packed, or obfuscated (suspicious in malware context).")
        _log("ERROR", fn, msg)
        return {"value": None, "status": "error", "error": str(exc),
                "hint": "Anomaly: valid MZ header but PE parsing failed — possible obfuscation/corruption.",
                "time_ms": round((time.perf_counter() - t0) * 1000, 2)}


def compute_section_hashes(path: Path) -> Dict[str, Any]:
    fn = "compute_section_hashes"
    _log("INFO", fn, f"Section hashing for: {path.name}")
    t0 = time.perf_counter()

    if _pefile is None:
        return {"value": None, "status": "unavailable",
                "error": "pefile not installed.", "hint": "pip install pefile"}
    try:
        pe = _pefile.PE(str(path))
        sections = {}
        for sec in pe.sections:
            try:
                name = sec.Name.rstrip(b"\x00").decode("utf-8", errors="replace")
                raw = sec.get_data()
                h   = hashlib.md5(raw).hexdigest()
                ent = calculate_entropy(raw)
                vsize  = sec.Misc_VirtualSize
                rsize  = sec.SizeOfRawData
                anomaly = None
                if vsize > 0 and rsize == 0:
                    anomaly = "VirtualSize > 0 but RawSize = 0 (possibly packed/injected)"
                if ent > 7.2:
                    anomaly = (anomaly or "") + f" High entropy ({ent}) — may be packed/encrypted"
                sections[name] = {
                    "md5": h,
                    "entropy": ent,
                    "virtual_size": vsize,
                    "raw_size": rsize,
                    "anomaly": anomaly
                }
                if anomaly:
                    _log("WARNING", fn, f"Section '{name}': {anomaly}")
            except Exception as exc:
                _log("ERROR", fn, f"Section parse error: {exc}")
        pe.close()
        elapsed = round((time.perf_counter() - t0) * 1000, 2)
        _log("INFO", fn, f"{len(sections)} sections hashed in {elapsed} ms.")
        return {"value": sections, "status": "ok", "time_ms": elapsed}
    except _pefile.PEFormatError:
        return {"value": None, "status": "skipped",
                "error": "Not a PE file.", "hint": "Expected for non-executables."}
    except Exception as exc:
        msg = f"Section hashing failed: {type(exc).__name__}: {exc}"
        _log("ERROR", fn, msg)
        return {"value": None, "status": "error", "error": msg,
                "hint": "Anomaly: PE load succeeded but section enumeration failed."}


def check_pe_signature(path: Path) -> Dict[str, Any]:
    fn = "check_pe_signature"
    _log("INFO", fn, f"Checking PE signature: {path.name}")
    if _pefile is None:
        return {"value": "N/A", "status": "unavailable", "error": "pefile not installed."}
    try:
        pe = _pefile.PE(str(path))
        signed = hasattr(pe, "DIRECTORY_ENTRY_SECURITY") and bool(pe.DIRECTORY_ENTRY_SECURITY)
        pe.close()
        val = "SIGNED" if signed else "NOT_SIGNED"
        _log("INFO", fn, f"Signature status: {val}")
        return {"value": val, "status": "ok"}
    except _pefile.PEFormatError:
        return {"value": "NOT_PE", "status": "skipped", "hint": "Not a PE file."}
    except Exception as exc:
        return {"value": None, "status": "error", "error": str(exc)}


# ─────────────────────────────────────────────
#  SECTION 6 ─ ENTROPY UTILITY
# ─────────────────────────────────────────────

def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    return round(-sum((f / n) * math.log2(f / n) for f in freq if f), 4)


# ─────────────────────────────────────────────
#  SECTION 7 ─ FILE METADATA
# ─────────────────────────────────────────────

def get_file_metadata(path: Path) -> Dict[str, Any]:
    fn = "get_file_metadata"
    _log("INFO", fn, f"Gathering metadata for: {path}")
    try:
        stat = path.stat()
        mime = "unknown"
        if _magic:
            try:
                mime = _magic.from_file(str(path), mime=True)
            except Exception as exc:
                _log("WARNING", fn, f"python-magic failed: {exc}. Falling back to mimetypes.")
                mime = mimetypes.guess_type(path.name)[0] or "unknown"
        else:
            mime = mimetypes.guess_type(path.name)[0] or "unknown"

        meta = {
            "file_name":  path.name,
            "path":       str(path.resolve()),
            "size_bytes": stat.st_size,
            "size_human": _human_size(stat.st_size),
            "created":    datetime.fromtimestamp(stat.st_ctime).strftime("%Y-%m-%d %H:%M:%S"),
            "modified":   datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
            "mime_type":  mime,
            "platform":   platform.system(),
        }
        _log("INFO", fn, f"Metadata OK. Size={meta['size_human']}, MIME={mime}")
        return meta
    except Exception as exc:
        _log("ERROR", fn, f"Metadata collection failed: {exc}")
        return {"error": str(exc)}


def _human_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.1f} {unit}"
        n /= 1024


# ─────────────────────────────────────────────
#  SECTION 8 ─ ORCHESTRATOR
# ─────────────────────────────────────────────

def analyze_file(path: Path, verbose: bool = False) -> Dict[str, Any]:
    """
    Master function: run all analysis modules, collect results,
    guarantee partial output even on multi-component failures.
    """
    fn = "analyze_file"
    run_start = time.perf_counter()
    _log("INFO", fn, f"═══ BEGIN ANALYSIS  run_id={_RUN_ID}  file={path} ═══")

    result: Dict[str, Any] = {
        "run_id":    _RUN_ID,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "file":      {},
        "hashes":    {},
        "fuzzy":     {},
        "pe":        {},
        "entropy":   {},
        "errors":    [],
    }

    # ── 1. Validate path ──────────────────────────────────────────────
    if not path.exists():
        msg = f"File not found: {path}"
        _log("ERROR", fn, msg)
        result["errors"].append({"component": "file_validation", "message": msg})
        return result

    if not path.is_file():
        msg = f"Path is not a regular file: {path}"
        _log("ERROR", fn, msg)
        result["errors"].append({"component": "file_validation", "message": msg})
        return result

    # ── 2. Metadata ───────────────────────────────────────────────────
    result["file"] = get_file_metadata(path)

    # ── 3. Read file ──────────────────────────────────────────────────
    _log("INFO", fn, "Reading file into memory…")
    data, read_err = _stream_file(path)

    if read_err == "PERMISSION_DENIED":
        msg = "Cannot read file: permission denied."
        _log("ERROR", fn, msg + "\n  Suggested: Run as administrator/root, or check file ACLs.")
        result["errors"].append({"component": "file_read", "message": msg,
                                 "hint": "Run as elevated user or check permissions."})
        return result  # Cannot proceed at all

    if read_err == "FILE_TOO_LARGE":
        _log("WARNING", fn, "File too large to buffer fully — fuzzy hashes will be skipped.")
        result["errors"].append({
            "component": "fuzzy_hashing",
            "message": "File exceeds 512 MB buffer limit.",
            "hint": "Expected limitation — fuzzy hashing requires full file in memory."
        })
        data = None  # fuzzy will be skipped; standard hashes need re-stream below

    if read_err and read_err not in ("FILE_TOO_LARGE",):
        msg = f"File read error: {read_err}"
        _log("ERROR", fn, msg)
        result["errors"].append({"component": "file_read", "message": msg})
        return result

    # For large files: stream again just for standard hashes
    if data is None:
        _log("INFO", fn, "Re-streaming large file for standard hashes only…")
        chunks = []
        try:
            with open(path, "rb") as fh:
                for chunk in iter(lambda: fh.read(CHUNK_SIZE), b""):
                    chunks.append(chunk)
            data_for_std = b"".join(chunks)
        except Exception as exc:
            _log("ERROR", fn, f"Re-stream failed: {exc}")
            data_for_std = b""
    else:
        data_for_std = data

    # ── 4. Standard hashes ────────────────────────────────────────────
    _log("INFO", fn, "Running standard hash suite…")
    result["hashes"] = compute_standard_hashes(data_for_std)

    # ── 5. Entropy (whole file) ────────────────────────────────────────
    try:
        ent = calculate_entropy(data_for_std)
        hint = ""
        if ent > 7.2:
            hint = "HIGH ENTROPY — file may be packed, encrypted, or compressed. Suspicious in malware context."
            _log("WARNING", fn, hint)
        result["entropy"] = {
            "value": ent, "status": "ok",
            "interpretation": hint or ("Normal" if ent < 6.0 else "Slightly elevated")
        }
    except Exception as exc:
        msg = f"Entropy calculation failed: {exc}"
        _log("ERROR", fn, msg)
        result["entropy"] = {"value": None, "status": "error", "error": msg}

    # ── 6. Fuzzy hashes (only if data available) ──────────────────────
    if data is not None:
        result["fuzzy"]["ssdeep"] = compute_ssdeep(data)
        result["fuzzy"]["tlsh"]   = compute_tlsh(data)
    else:
        for k in ("ssdeep", "tlsh"):
            result["fuzzy"][k] = {"value": None, "status": "skipped",
                                  "error": "File too large to buffer."}

    # ── 7. PE analysis ────────────────────────────────────────────────
    if _is_pe_file(data_for_std[:4] if data_for_std else b""):
        _log("INFO", fn, "PE/MZ header detected — running PE analysis.")
        result["pe"]["imphash"]       = compute_imphash(path)
        result["pe"]["section_hashes"]= compute_section_hashes(path)
        result["pe"]["signature"]     = check_pe_signature(path)
    else:
        _log("INFO", fn, "Not a PE file — skipping PE analysis.")
        for k in ("imphash", "section_hashes", "signature"):
            result["pe"][k] = {"value": "N/A", "status": "skipped",
                               "hint": "File is not a Windows PE executable."}

    total_ms = round((time.perf_counter() - run_start) * 1000, 2)
    result["total_time_ms"] = total_ms
    _log("INFO", fn, f"═══ ANALYSIS COMPLETE  run_id={_RUN_ID}  {total_ms} ms ═══")
    return result


# ─────────────────────────────────────────────
#  SECTION 9 ─ REPORTER / DISPLAY MODULE
# ─────────────────────────────────────────────

def _status_color(status: str) -> str:
    return {
        "ok":          C.GREEN,
        "error":       C.RED,
        "skipped":     C.YELLOW,
        "unavailable": C.YELLOW,
    }.get(status, C.WHITE)


def print_report(result: Dict[str, Any]) -> None:
    """Pretty-print the analysis result to stdout."""

    div   = f"{C.CYAN}{'─' * 62}{S.RESET_ALL}"
    hdiv  = f"{C.CYAN}{'═' * 62}{S.RESET_ALL}"

    def h(title: str) -> str:
        return f"\n{hdiv}\n{C.CYAN}  {title}{S.RESET_ALL}\n{hdiv}"

    def row(label: str, val: Any, color: str = C.WHITE) -> None:
        print(f"  {C.YELLOW}{label:<20}{S.RESET_ALL} {color}{val}{S.RESET_ALL}")

    def hash_row(name: str, info: Dict) -> None:
        sc = _status_color(info.get("status", ""))
        val = info.get("value") or f"[{info.get('status','?').upper()}]"
        t   = f"  ({info['time_ms']} ms)" if "time_ms" in info else ""
        print(f"  {C.YELLOW}{name:<12}{S.RESET_ALL} {sc}{val}{S.RESET_ALL}{C.CYAN}{t}{S.RESET_ALL}")
        if info.get("hint") and info.get("status") != "ok":
            print(f"  {' ' * 12}  {C.MAGENTA}↳ {info['hint']}{S.RESET_ALL}")

    # Header
    print(h(f"FORENSIC FILE ANALYSIS   run_id={result.get('run_id','?')}"))

    # Metadata
    f = result.get("file", {})
    if f:
        row("File", f.get("file_name", ""))
        row("Path", f.get("path", ""))
        row("Size", f.get("size_human", ""))
        row("MIME", f.get("mime_type", ""))
        row("Modified", f.get("modified", ""))

    # Entropy
    ent = result.get("entropy", {})
    if ent.get("status") == "ok":
        ec = C.RED if ent["value"] > 7.2 else (C.YELLOW if ent["value"] > 6.0 else C.GREEN)
        row("Entropy", f"{ent['value']}  {ent.get('interpretation','')}", ec)

    # Standard Hashes
    print(h("STANDARD HASHES"))
    for name, info in result.get("hashes", {}).items():
        hash_row(name, info)

    # Fuzzy Hashes
    print(h("FUZZY HASHES"))
    for name, info in result.get("fuzzy", {}).items():
        hash_row(name.upper(), info)

    # PE Analysis
    print(h("PE ANALYSIS"))
    pe = result.get("pe", {})

    ih = pe.get("imphash", {})
    hash_row("IMPHASH", ih)

    sig = pe.get("signature", {})
    sc = C.GREEN if sig.get("value") == "SIGNED" else C.RED
    row("Signature", sig.get("value", "N/A"), sc)

    secs = pe.get("section_hashes", {})
    if secs.get("status") == "ok" and secs.get("value"):
        print(f"\n  {C.CYAN}Sections:{S.RESET_ALL}")
        for sname, sinfo in secs["value"].items():
            anom_c = C.RED if sinfo.get("anomaly") else C.GREEN
            print(f"  {C.YELLOW}  {sname:<12}{S.RESET_ALL} md5={sinfo['md5'][:16]}… "
                  f"entropy={sinfo['entropy']} {anom_c}{sinfo.get('anomaly','OK')}{S.RESET_ALL}")
    else:
        hash_row("SECTIONS", secs)

    # Errors summary
    errs = result.get("errors", [])
    if errs:
        print(h("WARNINGS / ERRORS"))
        for e in errs:
            print(f"  {C.RED}[{e.get('component','?').upper()}]{S.RESET_ALL} {e.get('message','')}")
            if e.get("hint"):
                print(f"  {C.MAGENTA}  ↳ {e['hint']}{S.RESET_ALL}")

    # Timing
    print(f"\n{div}")
    print(f"  Total analysis time: {C.CYAN}{result.get('total_time_ms','?')} ms{S.RESET_ALL}")
    print(div)
    print()


# ─────────────────────────────────────────────
#  SECTION 10 ─ CLI ENTRY POINT
# ─────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="forensic_hasher",
        description=(
            "Forensic File Hasher v1.0 — "
            "Production-grade static fingerprinting with enterprise logging."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python forensic_hasher.py malware.exe\n"
            "  python forensic_hasher.py sample.dll --verbose --json\n"
            "  python forensic_hasher.py file.bin --log-file /tmp/run.log\n"
        )
    )
    parser.add_argument("filepath",          help="File to analyze")
    parser.add_argument("--verbose", "-v",   action="store_true",
                        help="Enable DEBUG-level logging to console")
    parser.add_argument("--json",            action="store_true",
                        help="Output full results as JSON (in addition to normal display)")
    parser.add_argument("--log-file",        default="analysis.log", metavar="PATH",
                        help="Path to log file (default: analysis.log)")
    parser.add_argument("--quiet", "-q",     action="store_true",
                        help="Suppress console output (log file only)")
    args = parser.parse_args()

    # Reconfigure logger now that we have CLI args
    global log
    log = _build_logger(verbose=args.verbose, log_file=args.log_file)

    if args.quiet:
        # Silence console handler
        for h in log.handlers:
            if isinstance(h, logging.StreamHandler) and not isinstance(h, logging.FileHandler):
                h.setLevel(logging.CRITICAL + 1)

    _log("INFO", "main", f"Forensic Hasher v1.0 started. run_id={_RUN_ID}")
    _log("INFO", "main", f"Target: {args.filepath}")
    _log("INFO", "main", f"Platform: {platform.system()} {platform.version()}")
    _log("INFO", "main", f"Python: {sys.version}")

    path = Path(args.filepath)
    result = analyze_file(path, verbose=args.verbose)

    if not args.quiet:
        print_report(result)

    if args.json:
        out = path.with_suffix(".analysis.json")
        try:
            with open(out, "w", encoding="utf-8") as fh:
                json.dump(result, fh, indent=2)
            _log("INFO", "main", f"JSON output saved to: {out}")
            print(f"{C.GREEN}[✓] JSON saved → {out}{S.RESET_ALL}")
        except OSError as exc:
            _log("ERROR", "main", f"Failed to write JSON: {exc}")

    _log("INFO", "main", "Done.")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
🔐 Advanced Hash Calculator CLI Tool (Smart Default Edition)

"""

import argparse
import hashlib
import mimetypes
import os
import sys
import json
import csv
import math
import datetime
from pathlib import Path

# Optional modules
try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init()
except ImportError:
    Fore = Style = type('dummy', (), {'RESET_ALL': '', 'CYAN': '', 'YELLOW': '', 'RED': '', 'GREEN': ''})

try:
    from tqdm import tqdm
except ImportError:
    tqdm = None

try:
    import pefile
except ImportError:
    pefile = None

try:
    import magic
except ImportError:
    magic = None

try:
    import pyperclip
except ImportError:
    pyperclip = None

SUPPORTED_HASHES = [
    'md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512',
    'sha3_256', 'sha3_512', 'blake2b', 'blake2s', 'imphash'
]

def get_file_metadata(path: Path) -> dict:
    stat = path.stat()
    return {
        "File Name": path.name,
        "Path": str(path.resolve()),
        "Size (bytes)": stat.st_size,
        "Created": datetime.datetime.fromtimestamp(stat.st_ctime).isoformat(),
        "Modified": datetime.datetime.fromtimestamp(stat.st_mtime).isoformat(),
        "MIME Type": magic.from_file(str(path)) if magic else mimetypes.guess_type(path.name)[0] or "Unknown"
    }

def calculate_entropy(path: Path) -> float:
    with open(path, 'rb') as f:
        data = f.read()
    if not data:
        return 0.0
    byte_freq = [0] * 256
    for byte in data:
        byte_freq[byte] += 1
    entropy = -sum((freq / len(data)) * math.log2(freq / len(data)) for freq in byte_freq if freq)
    return round(entropy, 4)

def calculate_hash(path: Path, algo: str) -> str:
    if algo.lower() == 'imphash':
        if not pefile:
            return "Error: pefile module not available"
        try:
            pe = pefile.PE(str(path))
            return pe.get_imphash()
        except Exception as e:
            return f"Error: {str(e)}"
    try:
        h = hashlib.new(algo)
    except ValueError:
        return f"Error: Unsupported hash algorithm '{algo}'"
    try:
        with open(path, 'rb') as f:
            if tqdm:
                for chunk in tqdm(iter(lambda: f.read(8192), b""), desc=f"Hashing {algo.upper()}", unit="chunk"):
                    h.update(chunk)
            else:
                while chunk := f.read(8192):
                    h.update(chunk)
        return h.hexdigest()
    except Exception as e:
        return f"Error reading file: {str(e)}"

def compute_all_hashes(path: Path, algos: list) -> dict:
    return {algo.upper(): calculate_hash(path, algo) for algo in algos}

def verify_hash(path: Path, algo: str, expected_hash: str) -> bool:
    actual = calculate_hash(path, algo)
    return actual.lower() == expected_hash.lower()

def compare_files(file1: Path, file2: Path, algo: str) -> bool:
    return calculate_hash(file1, algo) == calculate_hash(file2, algo)

def check_pe_signature(path: Path) -> str:
    if not pefile:
        return "Error: pefile module not available"
    try:
        pe = pefile.PE(str(path))
        return "Signed" if hasattr(pe, 'DIRECTORY_ENTRY_SECURITY') else "Not Signed"
    except Exception as e:
        return f"Error: {e}"

def print_output(info, hashes, args, entropy=None, signature=None):
    print(f"{Fore.CYAN}📄 File Info:{Style.RESET_ALL}")
    for k, v in info.items():
        print(f"  {Fore.YELLOW}{k}:{Style.RESET_ALL} {v}")
    if entropy:
        print(f"  {Fore.YELLOW}Entropy:{Style.RESET_ALL} {entropy}")
    if signature:
        print(f"  {Fore.YELLOW}Signature:{Style.RESET_ALL} {signature}")

    print(f"\n{Fore.GREEN}🔢 Hashes:{Style.RESET_ALL}")
    for k, v in hashes.items():
        print(f"  {k:<10}: {v}")
    if args.copy:
        algo = args.copy.lower()
        if algo.upper() in hashes and pyperclip:
            pyperclip.copy(hashes[algo.upper()])
            print(f"{Fore.GREEN}[✓] Copied {algo.upper()} to clipboard.{Style.RESET_ALL}")

def export_output(path: Path, info, hashes, args, entropy=None, signature=None):
    export_data = {
        "File Info": info,
        "Hashes": hashes,
    }
    if entropy:
        export_data["Entropy"] = entropy
    if signature:
        export_data["Signature"] = signature

    try:
        if args.output == "json":
            out_file = path.with_suffix(".hash.json")
            with open(out_file, 'w') as f:
                json.dump(export_data, f, indent=4)
            print(f"[✓] JSON written to {out_file}")
        elif args.output == "csv":
            out_file = path.with_suffix(".hash.csv")
            with open(out_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(["Key", "Value"])
                for k, v in info.items():
                    writer.writerow([k, v])
                for k, v in hashes.items():
                    writer.writerow([k, v])
                if entropy:
                    writer.writerow(["Entropy", entropy])
                if signature:
                    writer.writerow(["Signature", signature])
            print(f"[✓] CSV written to {out_file}")
    except Exception as e:
        print(f"[✗] Failed to export: {e}")

def parse_verify(value):
    try:
        algo, hash_val = value.split(":", 1)
        return algo.lower(), hash_val
    except:
        raise argparse.ArgumentTypeError("Format must be algo:hash")

def main():
    parser = argparse.ArgumentParser(
        description="🔐 Advanced Hash Calculator CLI Tool",
        epilog="""
Examples:
  hash_calc.py file.exe --hashes sha256 md5
  hash_calc.py --compare file1 file2 --hashes sha1
  hash_calc.py my_folder --recursive --output json
  hash_calc.py test.bin --verify sha256:<hash>
  hash_calc.py malware.exe --hashes imphash

If no flags are passed, the tool defaults to showing md5, sha256, and imphash (if PE).
        """
    )
    parser.add_argument("filepath", nargs="?", help="Path to file or folder")
    parser.add_argument("--compare", nargs=2, help="Compare two files using specified hash algorithm (e.g., sha256)")
    parser.add_argument("--hashes", nargs="+", help="Specify which hash algorithms to use (or 'all')")
    parser.add_argument("--verify", type=parse_verify, help="Verify file against known hash: sha256:<hash>")
    parser.add_argument("--output", choices=["text", "json", "csv"], default="text")
    parser.add_argument("--recursive", action="store_true", help="Recursively hash files in folder")
    parser.add_argument("--entropy", action="store_true", help="Include file entropy")
    parser.add_argument("--signature", action="store_true", help="Check PE signature (Windows only)")
    parser.add_argument("--copy", help="Copy specific hash to clipboard (e.g., md5, sha256)")
    args = parser.parse_args()

    if args.hashes and args.hashes == ["all"]:
        args.hashes = SUPPORTED_HASHES

    if args.compare:
        f1, f2 = map(Path, args.compare)
        algo = args.hashes[0] if args.hashes else 'sha256'
        result = compare_files(f1, f2, algo)
        print(f"[✓] Files are {'identical' if result else 'different'} based on {algo.upper()}.")
        return

    if not args.filepath:
        parser.print_help()
        return

    path = Path(args.filepath)
    if not path.exists():
        print(f"[✗] File not found: {path}")
        return

    files = []
    if path.is_file():
        files = [path]
    elif path.is_dir() and args.recursive:
        files = [p for p in path.rglob('*') if p.is_file()]
    else:
        print(f"[✗] Invalid path or missing --recursive for folders.")
        return

    # Smart default behavior if no flags
    if not (args.hashes or args.entropy or args.signature or args.verify):
        args.hashes = ['md5', 'sha256']
        try:
            with open(files[0], 'rb') as f:
                header = f.read(2)
            is_pe = header == b'MZ'
        except Exception:
            is_pe = False

        if is_pe and pefile:
            args.hashes.append('imphash')
            print("[i] No options provided. Defaulting to MD5, SHA256, and IMPHASH (PE detected).")
        else:
            print("[i] No options provided. Defaulting to MD5 and SHA256.")

    if args.hashes:
        invalid = [h for h in args.hashes if h not in SUPPORTED_HASHES]
        if invalid:
            print(f"[✗] Unsupported hash algorithms: {', '.join(invalid)}")
            print(f"[i] Supported: {', '.join(SUPPORTED_HASHES)}")
            return

    for file in files:
        info = get_file_metadata(file)
        hashes = compute_all_hashes(file, args.hashes) if args.hashes else {}
        entropy_val = calculate_entropy(file) if args.entropy else None
        signature_val = check_pe_signature(file) if args.signature else None

        if args.output == "text":
            print_output(info, hashes, args, entropy_val, signature_val)
        else:
            export_output(file, info, hashes, args, entropy_val, signature_val)

        if args.verify:
            algo, known_hash = args.verify
            verified = verify_hash(file, algo, known_hash)
            print(f"[✓] Verification {'passed' if verified else 'failed'} for {algo.upper()}.")

if __name__ == "__main__":
    main()

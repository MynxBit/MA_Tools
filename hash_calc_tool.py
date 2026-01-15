#!/usr/bin/env python3
"""
🔐 Advanced Hash Calculator CLI Tool ( v3 🚀)
   - Single-pass streaming for ALL algorithms
   - Auto-dependency installer built-in (--install-deps)
   - SSDEEP & TLSH Fuzzy Hashing support
   - Multi-threaded recursive scanning
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
import concurrent.futures
import threading
import subprocess
import platform
from pathlib import Path

# --- Configuration ---
SUPPORTED_HASHES = [
    'md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512',
    'sha3_256', 'sha3_512', 'blake2b', 'blake2s', 
    'crc32', 'imphash', 'ssdeep', 'tlsh'
]

# --- Hardcoded Requirements ---
REQUIRED_PACKAGES = [
    "colorama",
    "tqdm",
    "pefile",
    "pyperclip",
    "ssdeep",
    "tlsh"
]

def install_dependencies():
    """
    Hardcoded feature to install all necessary packages.
    """
    print(f"📦 Starting Automated Dependency Installer...")
    
    # 1. OS-Specific Magic Library
    system = platform.system()
    magic_lib = "python-magic-bin" if system == "Windows" else "python-magic"
    packages = REQUIRED_PACKAGES + [magic_lib]

    print(f"   Detected OS: {system}")
    print(f"   Target Packages: {', '.join(packages)}")
    
    # 2. Install Loop
    for package in packages:
        print(f"\n[+] Installing {package}...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", package])
        except subprocess.CalledProcessError:
            print(f"   [!] Failed to install {package}. You might need build tools (C++).")
            if package in ['ssdeep', 'tlsh']:
                print(f"       Note: {package} often requires OS-level libraries (libfuzzy-dev, etc.)")
    
    print(f"\n✅ Installation process finished. Please restart the script.")

# --- Dependency Imports (Safe Mode) ---
try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init()
except ImportError:
    Fore = Style = type('dummy', (), {'RESET_ALL': '', 'CYAN': '', 'YELLOW': '', 'RED': '', 'GREEN': '', 'MAGENTA': '', 'BLUE': ''})

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

# Fuzzy Hashing Libraries
try:
    import ssdeep
    HAS_SSDEEP = True
except ImportError:
    HAS_SSDEEP = False

try:
    import tlsh
    HAS_TLSH = True
except ImportError:
    HAS_TLSH = False

# Thread-safe print lock for recursive mode
print_lock = threading.Lock()

def safe_print(msg):
    with print_lock:
        print(msg)

def get_file_metadata(path: Path) -> dict:
    try:
        stat = path.stat()
        mime = "Unknown"
        if magic:
            try:
                mime = magic.from_file(str(path), mime=True)
            except: pass
        elif mimetypes:
            mime = mimetypes.guess_type(path.name)[0] or "Unknown"

        return {
            "File Name": path.name,
            "Path": str(path.resolve()),
            "Size": f"{stat.st_size:,} bytes",
            "Created": datetime.datetime.fromtimestamp(stat.st_ctime).strftime('%Y-%m-%d %H:%M:%S'),
            "Modified": datetime.datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
            "MIME Type": mime
        }
    except Exception as e:
        return {"Error": str(e)}

def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    byte_freq = [0] * 256
    for byte in data:
        byte_freq[byte] += 1
    entropy = -sum((freq / len(data)) * math.log2(freq / len(data)) for freq in byte_freq if freq)
    return round(entropy, 4)

class SuperHasher:
    """
    Handles single-pass hashing for multiple algorithms to optimize I/O.
    """
    def __init__(self, algos, path: Path):
        self.algos = [a.lower() for a in algos]
        self.path = path
        self.results = {}
        self.hash_objs = {}
        self.crc_val = 0
        
        # Initialize hashlib objects
        for algo in self.algos:
            if algo in hashlib.algorithms_available:
                self.hash_objs[algo] = hashlib.new(algo)
            elif algo == 'crc32':
                self.hash_objs['crc32'] = 0 # Placeholder

        # Initialize SSDEEP
        self.ssdeep_obj = None
        if 'ssdeep' in self.algos and HAS_SSDEEP:
            self.ssdeep_obj = ssdeep.Hash()
        
        # TLSH requires full buffer usually, handled separately or accumulated
        self.tlsh_buffer = bytearray() if 'tlsh' in self.algos and HAS_TLSH else None

    def process(self, show_progress=False):
        file_size = self.path.stat().st_size
        
        # Helper for progress bar
        pbar = None
        if show_progress and tqdm:
            pbar = tqdm(total=file_size, unit='B', unit_scale=True, desc=f"Hashing {self.path.name}", ncols=100)

        try:
            with open(self.path, 'rb') as f:
                while True:
                    chunk = f.read(65536) # 64KB chunks
                    if not chunk:
                        break
                    
                    # Update Standard Hashes
                    for name, obj in self.hash_objs.items():
                        if name == 'crc32':
                            import zlib
                            self.crc_val = zlib.crc32(chunk, self.crc_val)
                        else:
                            obj.update(chunk)
                    
                    # Update SSDEEP
                    if self.ssdeep_obj:
                        self.ssdeep_obj.update(chunk)

                    # Buffer for TLSH (Memory warning for huge files!)
                    if self.tlsh_buffer is not None:
                        if len(self.tlsh_buffer) < 200 * 1024 * 1024: # Limit 200MB for TLSH
                            self.tlsh_buffer.extend(chunk)
                        else:
                            self.results['TLSH'] = "Skipped (>200MB)"
                            self.tlsh_buffer = None # Clear memory

                    if pbar:
                        pbar.update(len(chunk))
            
            if pbar: pbar.close()

            # --- Finalize Results ---
            
            # Standard
            for name, obj in self.hash_objs.items():
                if name == 'crc32':
                    self.results['CRC32'] = f"{self.crc_val & 0xFFFFFFFF:08x}"
                else:
                    self.results[name.upper()] = obj.hexdigest()

            # SSDEEP
            if self.ssdeep_obj:
                self.results['SSDEEP'] = self.ssdeep_obj.digest()
            elif 'ssdeep' in self.algos and not HAS_SSDEEP:
                self.results['SSDEEP'] = "N/A (Module Missing)"

            # TLSH
            if self.tlsh_buffer is not None:
                if len(self.tlsh_buffer) < 50: 
                    self.results['TLSH'] = "Error: Data too short"
                else:
                    self.results['TLSH'] = tlsh.hash(bytes(self.tlsh_buffer))
            elif 'tlsh' in self.algos and not HAS_TLSH:
                self.results['TLSH'] = "N/A (Module Missing)"

            # IMPHASH (Requires PEfile)
            if 'imphash' in self.algos:
                if pefile:
                    try:
                        pe = pefile.PE(str(self.path))
                        self.results['IMPHASH'] = pe.get_imphash()
                        pe.close()
                    except pefile.PEFormatError:
                        self.results['IMPHASH'] = "Not a PE file"
                    except Exception as e:
                        self.results['IMPHASH'] = f"Error: {e}"
                else:
                    self.results['IMPHASH'] = "N/A (Module Missing)"

        except Exception as e:
            return {"Error": f"Read Failed: {e}"}

        return self.results

def check_pe_signature(path: Path) -> str:
    if not pefile: return "N/A"
    try:
        pe = pefile.PE(str(path))
        is_signed = hasattr(pe, 'DIRECTORY_ENTRY_SECURITY') and pe.DIRECTORY_ENTRY_SECURITY
        pe.close()
        return f"{Fore.GREEN}Signed{Style.RESET_ALL}" if is_signed else f"{Fore.RED}Not Signed{Style.RESET_ALL}"
    except:
        return "N/A"

def process_file_job(file_path, args, is_recursive=False):
    try:
        # Determine Algorithms
        if not args.hashes:
            current_algos = SUPPORTED_HASHES.copy()
        else:
            current_algos = args.hashes.copy()

        # Compute Hashes
        hasher = SuperHasher(current_algos, file_path)
        hashes = hasher.process(show_progress=(not is_recursive and not args.quiet))

        # Metadata & Extras
        info = get_file_metadata(file_path)
        entropy_val = None
        if args.entropy:
            try:
                with open(file_path, 'rb') as f:
                    entropy_val = calculate_entropy(f.read())
            except: pass
            
        signature_val = None
        if args.signature:
            try:
                with open(file_path, 'rb') as f:
                    if f.read(2) == b'MZ':
                        signature_val = check_pe_signature(file_path)
            except: pass

        # Output Logic
        if args.output == "text":
            out_lines = []
            if is_recursive:
                out_lines.append(f"{Fore.CYAN}--- {file_path.name} ---{Style.RESET_ALL}")
            else:
                out_lines.append(f"{Fore.CYAN}📄 File Info:{Style.RESET_ALL}")
                for k, v in info.items():
                    out_lines.append(f"  {Fore.YELLOW}{k}:{Style.RESET_ALL} {v}")
            
            if entropy_val: out_lines.append(f"  {Fore.MAGENTA}Entropy:{Style.RESET_ALL} {entropy_val}")
            if signature_val: out_lines.append(f"  {Fore.MAGENTA}Signature:{Style.RESET_ALL} {signature_val}")
            
            if not is_recursive: out_lines.append(f"\n{Fore.GREEN}🔢 Hashes:{Style.RESET_ALL}")
            
            for k, v in hashes.items():
                if "Error" in str(v) or "Missing" in str(v) or "Not a PE" in str(v):
                    val_color = Fore.RED
                elif k in ["SSDEEP", "TLSH"]:
                    val_color = Fore.BLUE 
                else:
                    val_color = Fore.WHITE
                out_lines.append(f"  {k:<10}: {val_color}{v}{Style.RESET_ALL}")
            
            safe_print("\n".join(out_lines))
            
            if args.copy and not is_recursive:
                target = args.copy.upper()
                if target in hashes and pyperclip:
                    pyperclip.copy(hashes[target])
                    safe_print(f"{Fore.GREEN}[✓] Copied {target} to clipboard.{Style.RESET_ALL}")

        return {"path": str(file_path), "info": info, "hashes": hashes, "entropy": entropy_val}

    except Exception as e:
        safe_print(f"{Fore.RED}[✗] Error processing {file_path.name}: {e}{Style.RESET_ALL}")
        return None

def main():
    parser = argparse.ArgumentParser(
        description=f"{Fore.CYAN}🔐 Advanced Hash Calculator - SUPER EDITION v3{Style.RESET_ALL}",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Setup:
  Use --install-deps to automatically install required pip packages.

Defaults:
  If no --hashes are specified, ALL supported algorithms will be calculated.

Supported Algorithms:
  Standard: md5, sha1, sha256, sha512, crc32...
  Malware:  imphash, ssdeep, tlsh

Examples:
  python hash_super.py --install-deps
  python hash_super.py malware.exe
  python hash_super.py ./folder --recursive --threads 8
        """
    )
    parser.add_argument("filepath", nargs="?", help="Path to file or folder")
    parser.add_argument("--hashes", nargs="+", help="Specific hashes (md5, sha256, ssdeep, etc.)")
    parser.add_argument("--output", choices=["text", "json", "csv"], default="text", help="Output format")
    parser.add_argument("--recursive", action="store_true", help="Scan folders recursively")
    parser.add_argument("--threads", type=int, default=4, help="Number of threads for recursive scan")
    parser.add_argument("--entropy", action="store_true", help="Calculate Shannon Entropy")
    parser.add_argument("--signature", action="store_true", help="Check PE Authenticode signature")
    parser.add_argument("--copy", help="Copy specific hash to clipboard")
    parser.add_argument("--quiet", action="store_true", help="Suppress progress bars")
    parser.add_argument("--install-deps", action="store_true", help="🚀 Install all required dependencies automatically")
    
    args = parser.parse_args()

    # --- FEATURE: Auto-Installer ---
    if args.install_deps:
        install_dependencies()
        return
    # -------------------------------

    if not args.filepath:
        parser.print_help()
        return

    path = Path(args.filepath)
    if not path.exists():
        print(f"{Fore.RED}[✗] Path not found: {path}{Style.RESET_ALL}")
        return

    if args.hashes and "all" in args.hashes:
        args.hashes = SUPPORTED_HASHES

    # --- Execution Logic ---
    all_results = []

    if path.is_file():
        res = process_file_job(path, args)
        if res: all_results.append(res)
    
    elif path.is_dir():
        if not args.recursive:
            print(f"{Fore.RED}[✗] Target is a folder. Use --recursive to scan.{Style.RESET_ALL}")
            return

        files = list(path.rglob('*'))
        files = [f for f in files if f.is_file()]
        
        print(f"{Fore.CYAN}[i] Scanning {len(files)} files with {args.threads} threads...{Style.RESET_ALL}")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = {executor.submit(process_file_job, f, args, True): f for f in files}
            
            if tqdm and not args.quiet:
                kwargs = {'total': len(files), 'unit': 'file', 'desc': 'Processing'}
                for future in tqdm(concurrent.futures.as_completed(futures), **kwargs):
                    res = future.result()
                    if res: all_results.append(res)
            else:
                for future in concurrent.futures.as_completed(futures):
                    res = future.result()
                    if res: all_results.append(res)

    # --- Export Logic ---
    if args.output in ["json", "csv"] and all_results:
        out_path = path if path.is_file() else path / "scan_results"
        
        if args.output == "json":
            out_file = str(out_path) + ".json"
            if path.is_dir(): out_file = path / "batch_scan.json"
            with open(out_file, 'w') as f:
                json.dump(all_results, f, indent=4)
            print(f"{Fore.GREEN}[✓] Saved JSON report to {out_file}{Style.RESET_ALL}")
            
        elif args.output == "csv":
            out_file = str(out_path) + ".csv"
            if path.is_dir(): out_file = path / "batch_scan.csv"
            with open(out_file, 'w', newline='') as f:
                sample = all_results[0]
                headers = ["Path", "Size"] + list(sample['hashes'].keys())
                if args.entropy: headers.append("Entropy")
                writer = csv.writer(f)
                writer.writerow(headers)
                for res in all_results:
                    row = [res['path'], res['info'].get('Size')]
                    for h_key in sample['hashes'].keys():
                        row.append(res['hashes'].get(h_key, ""))
                    if args.entropy: row.append(res.get('entropy', ""))
                    writer.writerow(row)
            print(f"{Fore.GREEN}[✓] Saved CSV report to {out_file}{Style.RESET_ALL}")

if __name__ == "__main__":
    main()

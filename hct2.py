#!/usr/bin/env python3
"""
🔐 Advanced Hash Calculator CLI Tool (Super Edition v6 🚀)
   - FIXED: Universal TLSH wrapper that supports BOTH 'tlsh' and 'tlsh-python' libs
   - FIXED: 'Module has no attribute hash' error completely resolved
   - Single-pass streaming for ALL algorithms
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

# --- Smart Dependency Installer ---
def install_dependencies():
    print(f"📦 Starting Smart Dependency Installer...")
    system = platform.system()
    
    # 1. Standard Packages
    pkgs = ["colorama", "tqdm", "pefile", "pyperclip", "ppdeep"]
    
    # 2. OS-Specific Magic & TLSH
    if system == "Windows":
        pkgs.append("python-magic-bin") 
        pkgs.append("tlsh-python") # Windows Binary
    else:
        pkgs.append("python-magic")
        pkgs.append("python-tlsh")

    print(f"   Target Packages: {', '.join(pkgs)}\n")
    
    for package in pkgs:
        print(f"[+] Installing {package}...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", package])
        except subprocess.CalledProcessError:
            print(f"   [!] Failed to install {package}.")
    
    print(f"\n✅ Installation finished. Please restart the script.")

# --- Imports ---
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

# --- Fuzzy Hashing Imports ---

# 1. SSDEEP (via ppdeep)
HAS_SSDEEP = False
try:
    import ppdeep
    HAS_SSDEEP = True
except ImportError:
    pass

# 2. TLSH (Universal Wrapper)
HAS_TLSH = False
try:
    import tlsh
    HAS_TLSH = True
except ImportError:
    pass

def compute_tlsh(data_bytes):
    """
    Universal wrapper to handle the different TLSH library versions.
    """
    if not HAS_TLSH: return "N/A (Module Missing)"
    
    try:
        # METHOD 1: Standard 'tlsh' lib (Linux/Source build)
        if hasattr(tlsh, 'hash'):
            return tlsh.hash(data_bytes)
        
        # METHOD 2: 'tlsh-python' lib (Windows Binary)
        # It uses an object-oriented approach or 'forcehash'
        elif hasattr(tlsh, 'Tlsh'):
            t = tlsh.Tlsh()
            t.update(data_bytes)
            t.final()
            return t.hexdigest()
            
        # METHOD 3: Fallback for older 'tlsh-python'
        elif hasattr(tlsh, 'forcehash'):
            return tlsh.forcehash(data_bytes)
            
    except Exception as e:
        return f"Error: {str(e)}"
    
    return "Error: Unknown TLSH library version"

# Thread-safe print lock
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
    if not data: return 0.0
    byte_freq = [0] * 256
    for byte in data:
        byte_freq[byte] += 1
    entropy = -sum((freq / len(data)) * math.log2(freq / len(data)) for freq in byte_freq if freq)
    return round(entropy, 4)

class SuperHasher:
    def __init__(self, algos, path: Path):
        self.algos = [a.lower() for a in algos]
        self.path = path
        self.results = {}
        self.hash_objs = {}
        self.crc_val = 0
        
        for algo in self.algos:
            if algo in hashlib.algorithms_available:
                self.hash_objs[algo] = hashlib.new(algo)
            elif algo == 'crc32':
                self.hash_objs['crc32'] = 0

        # Buffers for fuzzy hashes
        self.full_buffer = None
        if ('ssdeep' in self.algos and HAS_SSDEEP) or ('tlsh' in self.algos and HAS_TLSH):
            self.full_buffer = bytearray()

    def process(self, show_progress=False):
        file_size = self.path.stat().st_size
        pbar = None
        if show_progress and tqdm:
            pbar = tqdm(total=file_size, unit='B', unit_scale=True, desc=f"Hashing {self.path.name}", ncols=100)

        try:
            with open(self.path, 'rb') as f:
                while True:
                    chunk = f.read(65536) # 64KB chunks
                    if not chunk: break
                    
                    # Standard Hashes
                    for name, obj in self.hash_objs.items():
                        if name == 'crc32':
                            import zlib
                            self.crc_val = zlib.crc32(chunk, self.crc_val)
                        else:
                            obj.update(chunk)
                    
                    # Buffer for Fuzzy Hashes
                    if self.full_buffer is not None:
                        if len(self.full_buffer) < 200 * 1024 * 1024:
                            self.full_buffer.extend(chunk)
                        else:
                            self.full_buffer = None # Disable if too big
                    
                    if pbar: pbar.update(len(chunk))
            
            if pbar: pbar.close()

            # --- Finalize ---
            for name, obj in self.hash_objs.items():
                if name == 'crc32': self.results['CRC32'] = f"{self.crc_val & 0xFFFFFFFF:08x}"
                else: self.results[name.upper()] = obj.hexdigest()

            # SSDEEP
            if 'ssdeep' in self.algos:
                if HAS_SSDEEP and self.full_buffer:
                    try: self.results['SSDEEP'] = ppdeep.hash(bytes(self.full_buffer))
                    except: self.results['SSDEEP'] = "Error"
                elif not HAS_SSDEEP: self.results['SSDEEP'] = "N/A (Module Missing)"
                else: self.results['SSDEEP'] = "Skipped (>200MB)"

            # TLSH (Using Wrapper)
            if 'tlsh' in self.algos:
                if HAS_TLSH and self.full_buffer:
                    if len(self.full_buffer) < 50: self.results['TLSH'] = "Error: Data too short"
                    else: self.results['TLSH'] = compute_tlsh(bytes(self.full_buffer))
                elif not HAS_TLSH: self.results['TLSH'] = "N/A (Module Missing)"
                else: self.results['TLSH'] = "Skipped (>200MB)"

            # IMPHASH
            if 'imphash' in self.algos:
                if pefile:
                    try:
                        pe = pefile.PE(str(self.path))
                        self.results['IMPHASH'] = pe.get_imphash()
                        pe.close()
                    except pefile.PEFormatError: self.results['IMPHASH'] = "Not a PE file"
                    except: self.results['IMPHASH'] = "Error"
                else: self.results['IMPHASH'] = "N/A (Module Missing)"

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
    except: return "N/A"

def process_file_job(file_path, args, is_recursive=False):
    try:
        algos = args.hashes.copy() if args.hashes else SUPPORTED_HASHES.copy()
        
        hasher = SuperHasher(algos, file_path)
        hashes = hasher.process(show_progress=(not is_recursive and not args.quiet))
        info = get_file_metadata(file_path)
        
        entropy_val = None
        if args.entropy:
            try:
                with open(file_path, 'rb') as f: entropy_val = calculate_entropy(f.read())
            except: pass

        signature_val = None
        if args.signature:
            try:
                with open(file_path, 'rb') as f:
                    if f.read(2) == b'MZ': signature_val = check_pe_signature(file_path)
            except: pass

        if args.output == "text":
            out = []
            if is_recursive: out.append(f"{Fore.CYAN}--- {file_path.name} ---{Style.RESET_ALL}")
            else:
                out.append(f"{Fore.CYAN}📄 File Info:{Style.RESET_ALL}")
                for k,v in info.items(): out.append(f"  {Fore.YELLOW}{k}:{Style.RESET_ALL} {v}")
            
            if entropy_val: out.append(f"  {Fore.MAGENTA}Entropy:{Style.RESET_ALL} {entropy_val}")
            if signature_val: out.append(f"  {Fore.MAGENTA}Signature:{Style.RESET_ALL} {signature_val}")
            
            if not is_recursive: out.append(f"\n{Fore.GREEN}🔢 Hashes:{Style.RESET_ALL}")
            for k, v in hashes.items():
                color = Fore.WHITE
                if "Error" in str(v) or "Missing" in str(v) or "Not a PE" in str(v): color = Fore.RED
                elif k in ["SSDEEP", "TLSH"]: color = Fore.BLUE
                out.append(f"  {k:<10}: {color}{v}{Style.RESET_ALL}")
            
            safe_print("\n".join(out))
            
            if args.copy and not is_recursive:
                if args.copy.upper() in hashes and pyperclip:
                    pyperclip.copy(hashes[args.copy.upper()])
                    safe_print(f"{Fore.GREEN}[✓] Copied to clipboard.{Style.RESET_ALL}")

        return {"path": str(file_path), "info": info, "hashes": hashes}

    except Exception as e:
        safe_print(f"{Fore.RED}[✗] Error: {e}{Style.RESET_ALL}")
        return None

def main():
    parser = argparse.ArgumentParser(
        description=f"{Fore.CYAN}🔐 Advanced Hash Calculator - SUPER EDITION v6{Style.RESET_ALL}",
        epilog="""
Setup:
  Run 'python hash_super.py --install-deps' to fix missing modules.
        """
    )
    parser.add_argument("filepath", nargs="?", help="Path to file or folder")
    parser.add_argument("--hashes", nargs="+", help="Specific hashes")
    parser.add_argument("--output", choices=["text", "json", "csv"], default="text")
    parser.add_argument("--recursive", action="store_true")
    parser.add_argument("--threads", type=int, default=4)
    parser.add_argument("--entropy", action="store_true")
    parser.add_argument("--signature", action="store_true")
    parser.add_argument("--copy", help="Copy hash to clipboard")
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("--install-deps", action="store_true", help="🚀 Install dependencies")
    
    args = parser.parse_args()

    if args.install_deps:
        install_dependencies()
        return

    if not args.filepath:
        parser.print_help()
        return

    path = Path(args.filepath)
    if not path.exists():
        print("Path not found.")
        return

    if args.hashes and "all" in args.hashes: args.hashes = SUPPORTED_HASHES

    all_results = []
    if path.is_file():
        res = process_file_job(path, args)
        if res: all_results.append(res)
    elif path.is_dir():
        files = [f for f in path.rglob('*') if f.is_file()]
        print(f"{Fore.CYAN}[i] Scanning {len(files)} files...{Style.RESET_ALL}")
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
            futures = {ex.submit(process_file_job, f, args, True): f for f in files}
            for fut in tqdm(concurrent.futures.as_completed(futures), total=len(files), disable=args.quiet):
                res = fut.result()
                if res: all_results.append(res)

    if args.output in ["json", "csv"] and all_results:
        out_path = path if path.is_file() else path / "scan_results"
        if args.output == "json":
            out_file = str(out_path) + ".json"
            if path.is_dir(): out_file = path / "batch_scan.json"
            with open(out_file, 'w') as f: json.dump(all_results, f, indent=4)
            print(f"{Fore.GREEN}[✓] Saved JSON to {out_file}{Style.RESET_ALL}")
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
                    for h_key in sample['hashes'].keys(): row.append(res['hashes'].get(h_key, ""))
                    if args.entropy: row.append(res.get('entropy', ""))
                    writer.writerow(row)
            print(f"{Fore.GREEN}[✓] Saved CSV to {out_file}{Style.RESET_ALL}")

if __name__ == "__main__":
    main()

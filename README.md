# RBX-Finder / ORC V2 — Universal Multi-Binary Analyzer & Offset Ledger

**RBX-Finder / ORC V2** is a standalone, high-performance reverse engineering and binary analysis framework built to unify binary parsing, symbol resolution, cross-reference (XRef) analysis, and offset management into a single cohesive tool. By integrating the capabilities of `elf_parser`, `header_generator`, `symbol_resolver`, and `xref_engine` with zero external dependencies, it provides a streamlined workflow for security researchers, reverse engineers, and dynamic instrumentation developers.

🔗 **Official GitHub Repository:**  
[https://github.com/MITTO-m4x/obf-db/](https://github.com/MITTO-m4x/obf-db/)

---

## 📥 Installation & Setup

The tool runs natively on **Python 3** with no third-party packages required. Clone the repository and launch it on your platform using the instructions below:

### 1. Android (via Termux)
Open **Termux** and run the following commands to update packages, install Git and Python, and clone the repository:
```bash
pkg update && pkg upgrade -y
pkg install git python -y
git clone [https://github.com/MITTO-m4x/obf-db.git](https://github.com/MITTO-m4x/obf-db.git)
cd obf-db
python3 rbx_finder.py -i

> Note for Termux Users: To scan APK files or shared libraries located in your device's internal storage, grant storage permissions first via termux-setup-storage, then target paths under /sdcard/Download/....
> 
2. Linux (Ubuntu / Debian / Arch / Kali)
Open your terminal and execute:
sudo apt update && sudo apt install git python3 -y
git clone [https://github.com/MITTO-m4x/obf-db.git](https://github.com/MITTO-m4x/obf-db.git)
cd obf-db
chmod +x rbx_finder.py
python3 rbx_finder.py -i

3. Windows (Windows 10 / 11)
 * Ensure Python 3 (with Add Python to PATH checked during installation) and Git are installed.
 * Open Command Prompt (CMD) or PowerShell and run:
git clone [https://github.com/MITTO-m4x/obf-db.git](https://github.com/MITTO-m4x/obf-db.git)
cd obf-db
python rbx_finder.py -i

🏗️ Core Architecture & Features
 * In-Memory APK & Multi-Binary Scanning Engine:
   Batch-analyze directories containing dozens of shared libraries (.so) simultaneously, or inspect .apk packages directly in memory to extract and analyze target architectures (arm64-v8a, x86_64) without manual extraction.
 * 100% Function Boundary Precision via .eh_frame_hdr:
   Parses DWARF / LSB exception frame unwind tables directly from compiler metadata to recover exact start and end boundaries for over 213,000+ functions.
 * Candidate Ledger & Confidence Scoring System:
   Automatically logs discovered addresses and offsets with confidence tiers (high, medium, low) and review states (needs_review, confirmed, rejected, live), backed by deterministic evidence chains (evidence) and fallback candidates (alternatives).
 * Interactive Probe Engine:
   Run instant command-line queries against ELF binaries to locate strings, wildcard byte patterns (e.g., 4?, ??), and XRefs while automatically resolving the enclosing parent function.
 * Interactive Questionnaire Wizard:
   Launching without arguments or with -i triggers a guided 8-step setup wizard to configure target paths, library filters, signature matching, struct_hints, and export formats.
 * Multi-Environment Export Suite:
   Generates 7 ready-to-use output artifacts in a single pass:
   * Profile.hpp — Clean C++ header file ready for direct project integration.
   * Profile_frida.js — Ready-to-run Frida script for dynamic hooking and runtime tracing.
   * Profile_ghidra.py — Ghidra Python script for automated function renaming and annotation.
   * Profile_ida.py — IDAPython script for symbol labeling inside IDA Pro.
   * Profile_ledger.json — Structured candidate ledger for auditing and team review.
   * Profile_summary.md — Human-readable Markdown statistical and analytical report.
   * Profile.json — Complete raw AST and symbol dump.
🚀 Usage Workflows
1. Full APK Analysis Targeting a Specific Library
python3 rbx_finder.py /path/to/target.apk \
  --lib libroblox.so \
  --export-all ./output/roblox_build

2. Targeted Signature Scanning (signatures.json)
python3 rbx_finder.py /path/to/libs_dir/ \
  --sig-path signatures.json \
  --sig-filter "loadstring,resume,datamodel,securityfiltercapabilities" \
  --export-all ./output/filtered_build

3. Instant Queries via the Probe Engine
# Search for a string and identify its enclosing function
python3 rbx_finder.py probe libroblox.so string "Script Context"

# Search for a byte pattern with wildcard support
python3 rbx_finder.py probe libroblox.so pattern "FD 7B BE A9 ?? ?? ?? ??"

# Trace XRefs pointing to a specific address
python3 rbx_finder.py probe libroblox.so xref 0x3A2B1C

# List function entry points recovered from .eh_frame_hdr
python3 rbx_finder.py probe libroblox.so functions --limit 25

4. Candidate Ledger Management & Auditing
# Display statistical summary of confidence levels and review states
python3 rbx_finder.py ledger summary ./output/roblox_build_ledger.json

# Inspect candidates flagged for review
python3 rbx_finder.py ledger review ./output/roblox_build_ledger.json

# Confirm or reject a candidate with audit notes
python3 rbx_finder.py ledger mark ./output/roblox_build_ledger.json \
  --name loadstring \
  --status confirmed \
  --note "Verified via Ghidra decompilation" \
  --by analyst_1

# Validate ledger integrity and detect offset collisions
python3 rbx_finder.py ledger check ./output/roblox_build_ledger.json

⚙️ CLI Reference
| Argument / Flag | Description |
|---|---|
| target | Path to a .so binary, a directory of libraries, or an .apk file |
| --mode | Analysis depth mode (fast [default], normal, deep, paranoid) |
| --all-libs | Scan all libraries within the target directory or APK archive |
| --lib | Restrict analysis to a specific library by name (e.g., libroblox.so) |
| --sig-path | Path to a custom signatures.json file |
| --sig-filter | Comma-separated list of signature names to filter |
| --no-patterns | Disable byte-pattern scanning for faster execution |
| --no-struct-hints | Disable structure offset inference (struct_hints) |
| --min-len | Minimum character length for indexed strings (default: 4) |
| --export-all | Export all 7 output formats using the specified file prefix |
| --interactive, -i | Launch the step-by-step interactive setup wizard |
| --quiet | Suppress banners and verbose logs for silent execution |


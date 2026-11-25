# RBX-Finder / ORC V2 — Universal Multi-Binary Analyzer & Offset Ledger

**RBX-Finder / ORC V2** is a comprehensive, standalone reverse engineering and binary analysis framework that unifies all previous legacy tools (`elf_parser`, `header_generator`, `symbol_resolver`, `xref_engine`) into a single, self-contained, high-performance Python file with zero external dependencies. It provides full support for multi-library batch analysis, direct in-memory APK extraction and inspection, exact function boundary decoding via `.eh_frame_hdr`, Candidate Ledger lifecycle management, an instant Interactive Probe engine, and a guided 8-step Interactive Questionnaire Wizard.

🔗 **Official GitHub Repository:**  
[https://github.com/MITTO-m4x/obf-db/](https://github.com/MITTO-m4x/obf-db/)

---

## 📥 Installation & Setup Guide

**RBX-Finder / ORC V2** requires only **Python 3** (standard library only — no `pip` packages or third-party dependencies required). Follow the instructions for your platform below to clone the repository and get started:

### 1. Android (via Termux)
Open **Termux** and run the following commands to update your environment, install `git` and `python`, and clone the repository:
```bash
pkg update && pkg upgrade -y
pkg install git python -y
git clone https://github.com/MITTO-m4x/obf-db.git https://github.com/MITTO-m4x/obf-db.git
cd obf-db
python3 rbx_finder.py -i
```
> **Storage Access Tip for Termux:** If your `.apk` files or extracted `.so` libraries are stored in your device's internal storage, run `termux-setup-storage` once to grant permissions, then pass paths like `/sdcard/Download/roblox.apk` directly to the tool.

### 2. Linux (Ubuntu / Debian / Kali / Arch)
Open your terminal and execute:
```bash
sudo apt update && sudo apt install git python3 -y
git clone [https://github.com/MITTO-m4x/obf-db.git](https://github.com/MITTO-m4x/obf-db.git)
cd obf-db
chmod +x rbx_finder.py
python3 rbx_finder.py -i
```

### 3. Windows (Windows 10 / 11)
1. Install **Python 3** (make sure **"Add Python to PATH"** is checked during installation) and **Git for Windows**.
2. Open **Command Prompt (CMD)** or **PowerShell** and run:
```powershell
git clone [https://github.com/MITTO-m4x/obf-db.git](https://github.com/MITTO-m4x/obf-db.git)
cd obf-db
python rbx_finder.py -i
```

---

## 🌟 Core Features & Capabilities

### 1. Multi-Binary & Direct In-Memory APK Support
* **Batch Directory Scanning:** Analyze directories containing multiple shared object libraries simultaneously (`libbacktrace-native.so`, `libdatastore_shared_counter.so`, `libimage_processing_util_jni.so`, `librenderscript-toolkit.so`, `libroblox.so`, `libsurface_util_jni.so`, `libtrampoline.so`, `libzstd-jni-1.5.7-6.so`).
* **Zero-Extraction APK Inspection:** Directly load `.apk` archives in memory without needing external unzipping or extraction utilities, automatically detecting and analyzing native architecture libraries (`arm64-v8a`, `x86_64`).

### 2. 100% Function Boundary Precision via `.eh_frame_hdr`
* Parses and decodes compiler-generated DWARF / LSB exception frame unwind tables directly from the binary's `.eh_frame_hdr` and `.eh_frame` sections.
* Recovers the exact entry points and boundaries for **over 213,000+ functions** with deterministic accuracy, eliminating heuristic guesswork.

### 3. Smart Interactive Questionnaire Wizard (`-i`)
* Running the tool without arguments or passing `-i` / `--interactive` launches a guided **8-question setup wizard**.
* Walks you step-by-step through selecting your target (`.so`, directory, or `.apk`), target library filter, speed mode, signature file, keyword filters, byte-pattern scanning, structure offset inference, and output export prefixes.

### 4. Advanced Signature Engine (`signatures.json`)
* **Nibble-Level & Wildcard Pattern Matching:** Supports complex byte signatures featuring full-byte wildcards (`??`) as well as half-byte nibble masks (such as `4?` or `?F`).
* **Structure Offset Inference (`struct_hints`):** Automatically deduces critical internal structure offsets such as `Instance.children` and `TaskScheduler` fields.
* **Targeted Keyword Filtering (`--sig-filter`):** Isolate specific signatures for rapid builds using comma-separated keywords (e.g., `loadstring,resume,datamodel`).

### 5. Advanced Candidate Ledger Engine
* **Confidence & Review Classification:** Automatically categorizes every discovered offset and address by confidence tier (`high`, `medium`, `low`) and verification status (`needs_review`, `confirmed`, `rejected`, `live`).
* **Deterministic Evidence Chains:** Links each candidate to concrete proof (`evidence`) while preserving fallback matches (`alternatives`) for cross-version verification.
* **Built-in Ledger CLI Subcommands:** Includes dedicated workflow commands (`summary`, `review`, `mark`, `check`) to audit, verify, and maintain offset databases cleanly.

### 6. Instant Interactive Probe Engine
* Query any binary directly from the command line without running a full profile scan.
* Instantly locate strings, wildcard byte patterns, cross-references (XRefs), and `.eh_frame_hdr` function lists while automatically resolving the exact enclosing parent function for every match.

### 7. Multi-Format Export Suite (`--export-all`)
Generates 7 synchronized output files tailored for every reverse engineering and development environment in a single run:
* `Profile.hpp` — Ready-to-include C++ header file for external/internal projects and mods.
* `Profile_ledger.json` — Complete Candidate Ledger database for auditing and version tracking.
* `Profile_frida.js` — Ready-to-run Frida script for live dynamic hooking and function tracing.
* `Profile_ghidra.py` — Ghidra Python script for automated function renaming and comment injection.
* `Profile_ida.py` — IDC / IDAPython script for symbol labeling and annotation in IDA Pro.
* `Profile_summary.md` — Comprehensive statistical and analytical report formatted in Markdown.
* `Profile.json` — Complete raw AST, symbol table, and metadata dump.

---

## 🚀 Quick Start & Usage Workflows

### 1. Interactive Wizard Mode
Launch the guided 8-step interactive setup wizard:
```bash
python3 rbx_finder.py
# Or explicitly:
python3 rbx_finder.py -i
```

### 2. Full Multi-Library Directory Scan with Complete Export
Scan an entire folder of extracted `.so` libraries and export all 7 formats:
```bash
python3 rbx_finder.py \
  /path/to/extracted_libs/ \
  --export-all /path/to/output/roblox_profile
```

### 3. Direct APK Scan Targeting `libroblox.so` Only
Inspect an `.apk` directly in memory while filtering strictly for `libroblox.so`:
```bash
python3 rbx_finder.py \
  /path/to/roblox.apk \
  --lib libroblox.so \
  --export-all /path/to/output/roblox_profile
```

### 4. Custom Signature Scan with Keyword Filtering (`signatures.json`)
Run a targeted scan using a custom signature database and specific symbol filters:
```bash
python3 rbx_finder.py \
  /path/to/extracted_libs/ \
  --sig-path signatures.json \
  --sig-filter "loadstring,resume,datamodel,securityfiltercapabilities" \
  --export-all /path/to/output/filtered_profile
```

---

## 🔍 Interactive Probe Engine

Inspect any `.so` binary instantaneously from the terminal without running a full scan:

* **Locate a string and resolve its enclosing parent function:**
  ```bash
  python3 rbx_finder.py probe libroblox.so string "Script Context"
  ```

* **Search for a byte pattern (with wildcard and nibble support):**
  ```bash
  python3 rbx_finder.py probe libroblox.so pattern "FD 7B BE A9 ?? ?? ?? ??"
  ```

* **Trace all XRefs pointing to a specific virtual address:**
  ```bash
  python3 rbx_finder.py probe libroblox.so xref 0x3A2B1C
  ```

* **List exact function entry points extracted from `.eh_frame_hdr`:**
  ```bash
  python3 rbx_finder.py probe libroblox.so functions --limit 20
  ```

---

## 📋 Candidate Ledger Management

Manage, verify, and audit your extracted offsets using the built-in `ledger` subcommands:

* **Display a statistical summary of the ledger:**
  ```bash
  python3 rbx_finder.py ledger summary roblox_profile_ledger.json
  ```

* **Perform a detailed review of flagged candidates:**
  ```bash
  python3 rbx_finder.py ledger review roblox_profile_ledger.json
  ```

* **Confirm or reject a candidate with reviewer metadata:**
  ```bash
  python3 rbx_finder.py ledger mark roblox_profile_ledger.json \
    --name loadstring \
    --status confirmed \
    --note "Verified via Ghidra decompilation" \
    --by c4
  ```

* **Audit ledger integrity and check for address/offset conflicts:**
  ```bash
  python3 rbx_finder.py ledger check roblox_profile_ledger.json
  ```

---
---

## 🤖 AI Agent & LLM Integration

**RBX-Finder / ORC V2** is built with an **AI-First CLI architecture**, making it effortless to connect with modern AI coding assistants and autonomous agents (such as **Claude Code**, **Cursor**, **Aider**, **Gemini CLI**, or **OpenAI Codex**).

### How to Connect RBX-Finder to Your AI Workflow
1. **Direct CLI Execution (Agentic Tool Use):**  
   Because the tool features non-interactive flags (`--quiet`, `--export-all`, `probe`, and `ledger`), AI agents with terminal access can run targeted queries directly against binaries without getting stuck in interactive menus.
2. **Structured JSON & Markdown Context Ingestion:**  
   Feed `Profile_summary.md` or `Profile_ledger.json` directly into your LLM's context window so the AI can audit low-confidence offsets, compare cross-version diffs, or explain XRef chains.
3. **Automated Ghidra / Frida Script Generation:**  
   Use the exported `Profile_frida.js` and `Profile_ghidra.py` files as grounded base templates for the AI to extend with custom hooks or decompilation annotations.

### 📋 Ready-to-Use AI System Prompt (Copy & Paste)

Give the following prompt to your AI assistant inside your project workspace so it understands how to operate `rbx_finder.py` autonomously:

```text
You are an expert Reverse Engineering & Binary Analysis Assistant equipped with the `rbx_finder.py` (RBX-Finder / ORC V2) CLI tool located in the current workspace.

Your workflow for analyzing binaries, resolving symbols, and auditing offsets is as follows:
1. **Never guess offsets or function boundaries.** Always use `rbx_finder.py` to extract deterministic ground-truth data from `.eh_frame_hdr` and signature rules.
2. **Fast Inspection (`probe`):** When asked to locate a string, byte pattern, or XRef in a `.so` binary, run:
   - `python3 rbx_finder.py probe <binary.so> string "<query>"`
   - `python3 rbx_finder.py probe <binary.so> pattern "<hex_pattern_with_wildcards>"`
   - `python3 rbx_finder.py probe <binary.so> xref <0xAddress>`
   - `python3 rbx_finder.py probe <binary.so> functions --limit 25`
3. **Batch & APK Analysis:** When analyzing a full `.apk` or directory of libraries, execute:
   - `python3 rbx_finder.py <target> --lib libroblox.so --export-all ./output/profile --quiet`
4. **Candidate Ledger Auditing:** Read `./output/profile_ledger.json` and `./output/profile_summary.md` to review `needs_review` or `low` confidence candidates. Verify evidence chains and update statuses using:
   - `python3 rbx_finder.py ledger mark <ledger.json> --name <symbol> --status <confirmed|rejected> --note "<reasoning>" --by ai-assistant`
   - `python3 rbx_finder.py ledger check <ledger.json>`

Always verify ledger integrity after making updates and provide concise, technical explanations backed by exact virtual addresses and evidence chains.
```

## ⚙️ Complete CLI Arguments Reference

| Argument / Flag | Description |
| :--- | :--- |
| `target` | Path to a single `.so` file, a directory of libraries, or an `.apk` archive |
| `--mode` | Analysis speed/depth mode (`fast` [default], `normal`, `deep`, `paranoid`) |
| `--all-libs` | Scan all libraries present inside the target directory or APK archive |
| `--lib` | Target a specific library by filename only (e.g., `libroblox.so`) |
| `--sig-path` | Specify the path to a custom `signatures.json` file |
| `--sig-filter` | Filter signature names using a comma-separated list (e.g., `loadstring,resume`) |
| `--no-patterns` | Disable byte-pattern scanning |
| `--no-struct-hints` | Disable structure offset extraction (`struct_hints`) |
| `--min-len` | Set the minimum character length for indexed strings (default: `4`) |
| `--export-all` | Export all formats (`.hpp`, `_frida.js`, `_ghidra.py`, `_ida.py`, `_ledger.json`, `_summary.md`, `.json`) using the specified prefix |
| `--interactive`, `-i` | Launch the step-by-step interactive questionnaire wizard |
| `--quiet` | Suppress banners and status messages for silent execution |


<div align="center">

# 🔍 RBX-Finder / ORC V2
### Universal Multi-Binary Analyzer & Offset Ledger

![Python Version](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS%20%7C%20Android%20(Termux)-2EA44F?style=for-the-badge&logo=linux&logoColor=white)
![Zero Dependencies](https://img.shields.io/badge/Dependencies-Zero%20(Stdlib%20Only)-FF6F00?style=for-the-badge&logo=pypi&logoColor=white)
![Architecture](https://img.shields.io/badge/Arch-ARM64%20%7C%20x86__64-8A2BE2?style=for-the-badge&logo=arm&logoColor=white)
![GitHub Repo](https://img.shields.io/badge/GitHub-MITTO--m4x%2Fobf--db-181717?style=for-the-badge&logo=github&logoColor=white)
![Status](https://img.shields.io/badge/Release-ORC%20V2-00C853?style=for-the-badge)

**A unified, zero-dependency reverse engineering and binary analysis framework built to inspect ELF/APK binaries, recover exact function boundaries via `.eh_frame_hdr`, manage offset ledgers, and automate cross-tool reporting.**

🔗 **Repository URL:**
https://github.com/MITTO-m4x/obf-db/

</div>

---

## 📖 Overview

**RBX-Finder / ORC V2** consolidates legacy binary analysis workflows (`elf_parser`, `header_generator`, `symbol_resolver`, and `xref_engine`) into a single, portable, self-contained Python engine. Built with a focus on **usability, portability, deterministic accuracy, and structured reporting**, it requires **no external third-party packages** and runs seamlessly across desktop and mobile environments.

---

## ✨ Features

- 📦 **Multi-Binary & Direct APK Support** — Batch-process entire directories of shared libraries (`.so`) or inspect `.apk` archives directly in memory (`arm64-v8a`, `x86_64`) without manual extraction.
- 🎯 **`.eh_frame_hdr` Function Boundary Recovery** — Decodes compiler-generated DWARF/LSB exception unwind tables to recover exact function entry points and boundaries.
- 🧭 **Interactive Setup Wizard (`-i`)** — Guided 8-step interactive CLI questionnaire to configure targets, filters, analysis modes, and export formats without memorizing flags.
- 🧬 **Advanced Signature & Pattern Engine (`signatures.json`)** — Supports full-byte wildcards (`??`), nibble-level masks (`4?`, `?F`), keyword filtering (`--sig-filter`), and structural offset inference (`struct_hints`).
- 🔎 **Instant Interactive Probe Engine** — Query strings, wildcard byte patterns, XRefs, and function tables on the fly with automatic parent-function resolution.
- 📋 **Candidate Ledger & Confidence Scoring** — Tracks discovered offsets with confidence levels (`high`, `medium`, `low`), review statuses (`needs_review`, `confirmed`, `rejected`, `live`), evidence chains, and fallback alternatives.
- 📤 **Multi-Format Export Suite** — Generates synchronized reports and scripts across C++, Python, JavaScript, Markdown, JSON, TXT, and CSV.
- 🌍 **Cross-Platform & Lightweight** — Runs natively on **Windows, Linux, macOS, and Android (Termux)** using only Python's standard library.

---

## 📦 Installation & Setup

Choose your platform below and follow the setup steps:

<details open>
<summary><b>🪟 Windows (Windows 10 / 11)</b></summary>

#### Requirements
- **Python 3.10+** (Ensure **"Add Python to PATH"** is checked during installation)
- **Git** (optional if downloading via ZIP)

#### 1. Clone the Repository
```powershell
git clone [https://github.com/MITTO-m4x/obf-db.git](https://github.com/MITTO-m4x/obf-db.git)
```

#### 2. Navigate to the Project Directory
```powershell
cd obf-db
```

#### 3. Start RBX-Finder
```powershell
python rbx_finder.py -i
```
> **Tip:** If the `python` command is unavailable, use the Windows Python Launcher:
> ```powershell
> py rbx_finder.py -i
> ```

#### Alternative: ZIP Installation
1. Open the repository URL: https://github.com/MITTO-m4x/obf-db/
2. Click **Code → Download ZIP** and extract the archive.
3. Open **PowerShell** or **CMD** inside the extracted folder.
4. Run `python rbx_finder.py -i`.

</details>

<details>
<summary><b>🐧 Linux (Ubuntu / Debian / Kali / Arch)</b></summary>

#### 1. Update Package Lists
```bash
sudo apt update
```

#### 2. Install Python and Git
```bash
sudo apt install python3 git -y
```

#### 3. Clone the Repository
```bash
git clone [https://github.com/MITTO-m4x/obf-db.git](https://github.com/MITTO-m4x/obf-db.git)
```

#### 4. Enter the Project Directory
```bash
cd obf-db
```

#### 5. Launch the Application
```bash
python3 rbx_finder.py -i
```

</details>

<details>
<summary><b>🍎 macOS</b></summary>

#### Requirements
- Homebrew, Python 3, and Git.

#### 1. Install Requirements
```bash
brew install python git
```

#### 2. Clone the Repository
```bash
git clone [https://github.com/MITTO-m4x/obf-db.git](https://github.com/MITTO-m4x/obf-db.git)
```

#### 3. Enter the Project Directory
```bash
cd obf-db
```

#### 4. Launch RBX-Finder
```bash
python3 rbx_finder.py -i
```

</details>

<details>
<summary><b>📱 Android — Termux</b></summary>

#### 1. Update Packages
```bash
pkg update -y && pkg upgrade -y
```

#### 2. Install Python and Git
```bash
pkg install python git -y
```

#### 3. Enable Shared Storage
```bash
termux-setup-storage
```
> Grant storage permission when prompted by Android.

#### 4. Clone the Repository
```bash
git clone [https://github.com/MITTO-m4x/obf-db.git](https://github.com/MITTO-m4x/obf-db.git)
```

#### 5. Navigate to the Project
```bash
cd obf-db
```

#### 6. Launch the Application
```bash
python3 rbx_finder.py -i
```

> **Shared Storage Path:** Access files in your phone's Downloads folder via `/storage/emulated/0/Download/` or `/sdcard/Download/`.

</details>

---

## 🚀 Usage

### Interactive Wizard Mode
Launch the guided step-by-step interactive CLI:
```bash
python3 rbx_finder.py -i
```

### Analyze a Single Binary
```bash
python3 rbx_finder.py file.so
```

### Analyze a Directory of Libraries
```bash
python3 rbx_finder.py ./libs/
```

### Inspect an APK Directly (Targeting a Specific Library)
```bash
python3 rbx_finder.py application.apk --lib libroblox.so
```

### Targeted Signature Scan & Full Export
```bash
python3 rbx_finder.py ./libs/ \
  --sig-path signatures.json \
  --sig-filter "loadstring,resume,datamodel" \
  --export-all ./output/profile
```

---

## 🔍 Interactive Probe Engine

Run instant, targeted queries on any `.so` binary without executing a full profile scan:

```bash
# Locate a string and resolve its enclosing parent function
python3 rbx_finder.py probe libroblox.so string "Script Context"

# Search for a byte pattern (supports ?? and nibble wildcards like 4?)
python3 rbx_finder.py probe libroblox.so pattern "FD 7B BE A9 ?? ?? ?? ??"

# Trace cross-references (XRefs) to a virtual address
python3 rbx_finder.py probe libroblox.so xref 0x3A2B1C

# List function entry points recovered from .eh_frame_hdr
python3 rbx_finder.py probe libroblox.so functions --limit 25
```

---

## 📋 Candidate Ledger Management

Audit, verify, and maintain discovered offsets using the built-in `ledger` subcommands:

```bash
# Display statistical summary of confidence tiers and review states
python3 rbx_finder.py ledger summary ./output/profile_ledger.json

# Review candidates flagged for verification
python3 rbx_finder.py ledger review ./output/profile_ledger.json

# Confirm or reject a candidate with reviewer notes
python3 rbx_finder.py ledger mark ./output/profile_ledger.json \
  --name loadstring \
  --status confirmed \
  --note "Verified via static disassembly" \
  --by MITTO

# Validate ledger integrity and check for address/offset conflicts
python3 rbx_finder.py ledger check ./output/profile_ledger.json
```

---

## ⚙️ Analysis Modes

RBX-Finder provides four analysis profiles to balance execution speed, depth, and resource usage:

| Mode | Description |
| :--- | :--- |
| `fast` | Quick analysis with reduced processing *(Default)* |
| `normal` | Balanced analysis for standard everyday workflows |
| `deep` | Extensive cross-reference and pattern analysis |
| `paranoid` | Intensive, exhaustive analysis profile |

> *Mode availability and exact behavior depend on the current implementation.*

---

## 🧰 Command-Line Options

| Option | Description |
| :--- | :--- |
| `target` | Input `.so` file, directory of libraries, or `.apk` archive |
| `--mode` | Select analysis mode (`fast`, `normal`, `deep`, `paranoid`) |
| `--all-libs` | Process all available library files in the target directory or APK |
| `--lib` | Restrict analysis to a specific library (e.g., `libroblox.so`) |
| `--sig-path` | Specify path to a custom `signatures.json` file |
| `--sig-filter` | Filter signature results using comma-separated keywords |
| `--no-patterns` | Disable byte-pattern scanning |
| `--no-struct-hints` | Disable structural offset inference (`struct_hints`) |
| `--min-len` | Configure minimum character length threshold for strings (default: `4`) |
| `--export-all` | Export generated analysis results across all supported formats |
| `-i`, `--interactive` | Launch the step-by-step interactive wizard mode |
| `--quiet` | Suppress banners and verbose console output |
| `-h`, `--help` | Display command-line help message |

For the most accurate list of supported options in your build, run:
```bash
python3 rbx_finder.py --help
```

---

## 📊 Output & Reports

Analysis results can be exported into multiple synchronized formats depending on your workflow:

### Supported Report & Integration Formats
- **C++ Header (`.hpp`)** — Ready-to-include definitions for native projects.
- **Candidate Ledger (`_ledger.json`)** — Organized candidate records with confidence scores and evidence chains.
- **Frida Script (`_frida.js`)** — Instrumentation template for runtime hooking and tracing.
- **Ghidra Script (`_ghidra.py`)** — Automated symbol renaming and annotation script for Ghidra.
- **IDA Script (`_ida.py`)** — IDAPython symbol labeling script for IDA Pro.
- **Markdown (`_summary.md`)** — Human-readable analytical and statistical summary.
- **JSON / TXT / CSV** — Structured machine-readable data, plain-text logs, and tabular exports.

### Example Output Structure
```text
output/
├── profile.hpp
├── profile.json
├── profile_ledger.json
├── profile_summary.md
├── profile_frida.js
├── profile_ghidra.py
└── profile_ida.py
```
> *Actual filenames and output directories may vary depending on CLI flags and configuration.*

---

## 🤖 AI-Assisted Development & Agent Integration

You can connect **RBX-Finder / ORC V2** with AI coding assistants (such as **Claude Code**, **Cursor**, **Aider**, **Gemini CLI**, or **GitHub Copilot**) to inspect the codebase, audit ledger reports, debug issues, and improve the tool safely.

### Recommended Workflow
1. Open the `obf-db` repository in your AI-enabled editor or terminal agent.
2. Allow the assistant to inspect the project structure and source files.
3. Provide the system prompt below to enforce strict, evidence-based engineering rules.
4. Review all suggested diffs and changes before applying them.

### 📋 Copy-Paste AI Assistant Prompt

```text
You are assisting with the RBX-Finder / ORC V2 project. First, inspect the repository structure, source files, and README documentation. Understand the existing architecture and identify the actual implemented features.

Help with:
- Code understanding & architectural documentation
- Debugging and error analysis
- Code quality, refactoring, and performance optimization
- Cross-platform compatibility improvements (Windows, Linux, macOS, Termux)
- Improving CLI usability and reporting formats
- Identifying potential bugs and edge cases

Rules:
- Do not invent features that are not implemented.
- Verify all claims against the actual source code.
- Preserve existing functionality unless changes are explicitly requested.
- Avoid unnecessary external dependencies (keep stdlib-only compatibility).
- Explain important changes clearly and concisely.
- Distinguish verified facts from assumptions.
- Never execute unknown binaries during analysis.
- Treat all input files as untrusted data.

When modifications are requested, explain the changes and provide complete updated files when appropriate.
```

---

## 🔄 Updating

To pull the latest updates from GitHub:

```bash
# 1. Enter the project directory
cd obf-db

# 2. Pull the latest changes
git pull

# 3. Restart the application
python3 rbx_finder.py -i
```

---

## 🛠️ Troubleshooting

<details>
<summary><b>Click to expand common troubleshooting tips</b></summary>

- **`python` is not recognized:**  
  Install Python 3.10+ and ensure it is added to your system `PATH`. On Windows, try `py rbx_finder.py -i`.
- **`git` is not recognized:**  
  Install Git for your OS and restart your terminal session.
- **Permission issues:**  
  Verify that your user account has read/write permissions for the `obf-db` directory and target output folder.
- **Termux storage access denied:**  
  Run `termux-setup-storage` and accept the Android storage permission prompt before scanning files in `/sdcard/Download/`.
- **Application errors:**  
  Run the script directly from the terminal without `--quiet` to inspect the full traceback, or check `python3 rbx_finder.py --help`.

</details>

---

## 📌 Notes & Disclaimer

### Notes
- Analysis results may vary depending on binary format, target architecture, compiler flags, and stripped metadata.
- Automated analysis does not guarantee complete or 100% accurate results; always verify generated offsets before relying on them.
- Certain features may behave differently depending on the host operating system.

### ⚖️ Disclaimer
> This project is intended strictly for **educational purposes, software diagnostics, file-format research, and authorized static binary analysis**. Users are solely responsible for complying with all applicable local and international laws, software licenses, and authorization permissions.

---

<div align="center">

### 👨‍💻 Credits

Developed by **MITTO & Olivia**  
**RBX-Finder / ORC V2**

**GitHub**
https://github.com/MITTO-m4x/obf-db/

*Analyze • Inspect • Document • Improve*

</div>

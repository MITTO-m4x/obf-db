# RBX-Finder / ORC V2
### Universal Multi-Binary Analyzer & Offset Ledger

> A lightweight, standalone Python framework for binary inspection, ELF metadata analysis, APK archive inspection, batch processing, and structured reporting.

**RBX-Finder / ORC V2** brings multiple analysis workflows together in a unified command-line application, designed to work across desktop platforms and Android.

---

## ✨ Features

- **Multi-Binary Analysis** — Process individual files or entire directories.
- **APK Inspection** — Inspect archive contents and identify native libraries and ABI directories.
- **ELF Analysis** — Examine headers, architecture, sections, segments, and available metadata.
- **Batch Processing** — Analyze multiple supported files in one session.
- **Interactive Wizard** — Guided configuration for users who prefer interactive workflows.
- **Configurable Analysis** — Select analysis depth and optional inspection features.
- **Structured Reports** — Generate organized JSON and Markdown reports.
- **Candidate Ledger** — Organize findings, evidence, review status, and confidence.
- **Pattern Recognition** — Optional configurable binary-pattern analysis.
- **Cross-Platform** — Supports Windows, Linux, macOS, and Android through Termux.
- **Zero Dependencies** — Designed around Python's standard library.

---

## 📋 Requirements

- Python **3.9+**
- Git
- No additional Python packages required

---

# 📥 Installation

## 🪟 Windows

### Method 1 — Git

Install Python 3 and Git for Windows.

Open PowerShell:

```powershell
git clone https://github.com/MITTO-m4x/obf-db.git
cd obf-db
python rbx_finder.py --help

Launch interactive mode:

python rbx_finder.py -i

Method 2 — Download ZIP

1. Open the repository:
   https://github.com/MITTO-m4x/obf-db/
2. Click Code → Download ZIP.
3. Extract the archive.
4. Open the extracted project folder.
5. Open PowerShell or CMD inside the folder.

Run:

python rbx_finder.py -i

If Python is installed through the Windows launcher:

py rbx_finder.py -i

---

🐧 Linux

Supported distributions include Ubuntu, Debian, Kali, and other distributions with Python 3.

Install the requirements:

sudo apt update
sudo apt install python3 git -y

Clone the repository:

git clone https://github.com/MITTO-m4x/obf-db.git
cd obf-db

Run:

python3 rbx_finder.py -i

---

🍎 macOS

Install Requirements

If Python 3 is not installed, install it using Homebrew:

brew install python git

Clone the Repository

git clone https://github.com/MITTO-m4x/obf-db.git
cd obf-db

Launch

python3 rbx_finder.py -i

---

📱 Android — Termux

Install the required packages:

pkg update -y
pkg upgrade -y
pkg install python git -y

Grant storage access:

termux-setup-storage

Clone the project:

git clone https://github.com/MITTO-m4x/obf-db.git
cd obf-db

Launch the application:

python3 rbx_finder.py -i

Files located in shared storage can usually be accessed through:

/storage/emulated/0/Download/

Example:

/storage/emulated/0/Download/sample.apk

---

🚀 Usage

Interactive Mode

Launch the interactive wizard:

python3 rbx_finder.py -i

The wizard guides you through input selection, analysis configuration, filtering, and output options.

---

Command-Line Mode

Run the program directly with a supported input:

python3 rbx_finder.py <target>

Examples of targets include:

library.so
application.apk
./libraries/

---

Analysis Modes

Choose an analysis mode according to your requirements:

Mode| Description
"fast"| Quick inspection
"normal"| Standard analysis
"deep"| Extended inspection
"paranoid"| Additional validation

Example:

python3 rbx_finder.py input --mode normal

---

Output & Reports

The application can generate structured reports for reviewing and organizing analysis results.

Depending on the implemented export options, reports may include:

File| Description
".json"| Structured machine-readable data
".md"| Detailed Markdown summary
".txt"| Plain-text report
".csv"| Tabular data
"_ledger.json"| Organized review records

Example output directory:

output/
├── profile.json
├── profile_summary.md
├── profile.txt
├── profile.csv
└── profile_ledger.json

---

⚙️ Command-Line Options

Option| Description
"target"| Input file, archive, or directory
"--mode"| Select analysis mode
"--all-libs"| Process multiple supported libraries
"--lib"| Select files by filename
"--sig-path"| Specify a configuration file
"--sig-filter"| Filter configured analysis rules
"--no-patterns"| Disable optional pattern analysis
"--no-struct-hints"| Disable optional structural hints
"--min-len"| Set the minimum string length
"--export-all"| Generate supported output reports
"-i", "--interactive"| Launch the interactive wizard
"--quiet"| Reduce informational output
"-h", "--help"| Display command-line help

View the complete available options:

python3 rbx_finder.py --help

Available arguments may depend on the current project version.

---

📊 Analysis Workflow

A typical workflow consists of:

1. Select a supported input file or directory.
2. Validate the input and file format.
3. Collect available metadata.
4. Perform the selected analysis.
5. Organize findings and evidence.
6. Generate reports.
7. Review the results.

Automated findings may be incomplete and should not automatically be treated as verified results.

---

🤖 AI Assistant Integration

RBX-Finder can be used alongside AI coding assistants that support access to project files and terminal commands.

Examples include:

- ChatGPT
- Claude
- Gemini
- Cursor
- GitHub Copilot
- Other coding assistants

Connecting an AI Assistant

1. Open the project directory in your AI coding environment.
2. Allow the assistant to access the project files.
3. Provide the project instructions below.
4. Ask the assistant to explain the code, review errors, document features, or help with development.
5. Verify suggested changes before applying them.

AI Project Prompt

Copy this prompt into your AI assistant:

You are an AI development assistant working with the
RBX-Finder / ORC V2 project.

First, inspect the repository structure and read README.md
and the main Python source file.

Understand the implemented features, supported arguments,
dependencies, operating-system compatibility, and limitations.

Do not invent commands, functions, or capabilities.
Verify command-line options against the actual source code.

When assisting:
- Explain findings clearly.
- Identify bugs and compatibility issues.
- Suggest maintainable Python improvements.
- Preserve existing project behavior unless changes are requested.
- Avoid unnecessary dependencies.
- Provide complete code when a file replacement is requested.
- Clearly distinguish confirmed information from assumptions.
- Test changes where possible.
- Document new options and behavior accurately.

Treat all analyzed files as untrusted input.
Do not execute analyzed binaries.

---

🛠️ Troubleshooting

Python Not Found

Check your installation:

python --version

Or:

python3 --version

Windows:

py --version

Permission Issues

On Termux:

termux-setup-storage

On Linux/macOS, verify that you have permission to read the input files and write to the output directory.

Repository Already Exists

Navigate to the existing project:

cd obf-db
git pull

Command Not Recognized

Display the supported arguments:

python3 rbx_finder.py --help

---

🔒 Reliability

- Input validation
- Error handling
- Structured output
- File integrity checks
- Cross-platform compatibility
- Conservative confidence classification
- Safe handling of unsupported formats

Results depend on the input file, available metadata, architecture, and analysis methods.

---

📌 Disclaimer

RBX-Finder / ORC V2 is intended for educational purposes, software diagnostics, file-format research, and authorized analysis.

Users are responsible for ensuring that their activities comply with applicable laws, licenses, and permissions.

Automated analysis does not guarantee complete or accurate results.

---

👨‍💻 Credits

Developed by MITTO & Olivia

RBX-Finder / ORC V2

GitHub Repository:

https://github.com/MITTO-m4x/obf-db/

---

<p align="center">RBX-Finder / ORC V2

Analyze • Inspect • Document • Improve

</p>
```

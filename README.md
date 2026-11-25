RBX-Finder / ORC V2

Universal Multi-Binary Analyzer & Offset Ledger

RBX-Finder / ORC V2 is a multi-binary analysis utility designed to inspect files, organize analysis results, and generate structured reports through an interactive interface.

Built with a focus on usability, portability, organized output, and efficient analysis workflows.

---

✨ Features

- Multi-Binary Support — Analyze multiple files in a single workflow.
- APK Inspection — Inspect APK archives and discover contained files.
- ELF Analysis — Examine ELF file metadata and structural information.
- Batch Processing — Process multiple files or directories.
- Interactive Interface — Guided analysis through an interactive CLI.
- Analysis Modes — Different analysis profiles for varying workloads.
- Structured Reports — Export analysis results into organized formats.
- Candidate Ledger — Maintain a structured record of discovered results.
- Cross-Platform — Supports Windows, Linux, macOS, and Android through Termux.
- Lightweight — Designed to operate with minimal external dependencies.

---

📦 Installation & Setup

Choose your platform and follow the instructions below.

---

🪟 Windows

Requirements

- Python 3.10+
- Git (optional if downloading ZIP)

1. Clone the Repository

git clone https://github.com/MITTO-m4x/obf-db.git

2. Navigate to the Project Directory

cd obf-db

3. Start RBX-Finder

python rbx_finder.py -i

If the "python" command is unavailable, try:

py rbx_finder.py -i

Alternative: ZIP Installation

1. Open the GitHub repository.

2. Download the repository as a ZIP archive.

3. Extract the archive.

4. Open PowerShell inside the extracted folder.

5. Start the application:
   
   python rbx_finder.py -i

---

🐧 Linux

1. Update Package Lists

sudo apt update

2. Install Python and Git

sudo apt install python3 git -y

3. Clone the Repository

git clone https://github.com/MITTO-m4x/obf-db.git

4. Enter the Project Directory

cd obf-db

5. Launch the Application

python3 rbx_finder.py -i

---

🍎 macOS

Requirements

Python 3 and Git.

1. Install Requirements

brew install python git

2. Clone the Repository

git clone https://github.com/MITTO-m4x/obf-db.git

3. Enter the Project Directory

cd obf-db

4. Launch RBX-Finder

python3 rbx_finder.py -i

---

📱 Android — Termux

1. Update Packages

pkg update -y && pkg upgrade -y

2. Install Python and Git

pkg install python git -y

3. Enable Shared Storage

termux-setup-storage

Grant storage permission when prompted.

4. Clone the Repository

git clone https://github.com/MITTO-m4x/obf-db.git

5. Navigate to the Project

cd obf-db

6. Launch the Application

python rbx_finder.py -i

Shared Storage Location

/storage/emulated/0/Download/

---

🚀 Usage

Interactive Mode

Launch the interactive interface:

python rbx_finder.py -i

Analyze a File

python rbx_finder.py file.so

Analyze a Directory

python rbx_finder.py ./libs/

Inspect an APK

python rbx_finder.py application.apk

Export Results

python rbx_finder.py input --export-all ./output/profile

---

⚙️ Analysis Modes

RBX-Finder provides different analysis profiles intended to balance processing time, detail, and resource usage.

Mode| Description
Fast| Quick analysis with reduced processing
Normal| Balanced analysis for everyday use
Deep| More extensive analysis
Paranoid| Intensive analysis profile

Mode availability and exact behavior depend on the current implementation.

---

🧰 Command-Line Options

Option| Description
"target"| Input file or directory
"--mode"| Select analysis mode
"--all-libs"| Process available library files
"--lib"| Specify a library selection
"--sig-path"| Specify a signature source
"--sig-filter"| Filter signature results
"--no-patterns"| Disable pattern analysis
"--no-struct-hints"| Disable structural hints
"--min-len"| Configure minimum length threshold
"--export-all"| Export generated analysis results
"-i", "--interactive"| Launch interactive mode
"--quiet"| Reduce console output
"-h", "--help"| Display command-line help

For the most accurate list of supported options, run:

python rbx_finder.py --help

---

📊 Output & Reports

Analysis results may be organized into multiple output formats depending on the selected workflow.

Supported Report Formats

- JSON — Structured machine-readable data.
- Markdown — Readable analysis summaries.
- TXT — Plain-text reports.
- CSV — Tabular data.
- Ledger — Organized candidate records.

Example Output Structure

output/
├── analysis.json
├── analysis.md
├── analysis.txt
├── analysis.csv
└── candidate_ledger.json

Actual filenames and output directories may vary depending on configuration.

---

🤖 AI-Assisted Development

You can use an AI coding assistant to help understand, document, debug, and improve the project.

Recommended Workflow

1. Open the repository in your coding environment.
2. Allow the assistant to inspect the project files.
3. Provide the prompt below.
4. Review suggested changes before applying them.

AI Assistant Prompt

You are assisting with the RBX-Finder / ORC V2 project.

First, inspect the repository structure, source files,
and README documentation.

Understand the existing architecture and identify
the actual implemented features.

Help with:

- Code understanding
- Debugging and error analysis
- Documentation improvements
- Code quality
- Performance optimization
- Compatibility improvements
- Refactoring
- Improving CLI usability
- Identifying potential bugs

Rules:

- Do not invent features that are not implemented.
- Verify claims against the actual source code.
- Preserve existing functionality unless changes
  are explicitly requested.
- Avoid unnecessary dependencies.
- Explain important changes clearly.
- Distinguish verified facts from assumptions.
- Never execute unknown binaries during analysis.
- Treat input files as untrusted data.

When modifications are requested, explain the changes
and provide complete updated files when appropriate.

---

🔄 Updating

To update your local repository:

1. Enter the Project Directory

cd obf-db

2. Pull the Latest Changes

git pull

3. Restart the Application

python rbx_finder.py -i

---

🛠️ Troubleshooting

Python Is Not Recognized

Install Python and make sure it is available through your system PATH.

On Windows, try:

py rbx_finder.py -i

Git Is Not Recognized

Install Git and reopen your terminal.

Permission Issues

Check that your current user has permission to access the project directory.

Termux Storage Problems

Run:

termux-setup-storage

Then grant the required Android storage permissions.

Application Errors

Run the application from the terminal and review the error output.

For additional information:

python rbx_finder.py --help

---

📌 Notes

- Analysis results may vary depending on file format, architecture, and available information.
- Automated analysis does not guarantee complete or accurate results.
- Some features may behave differently depending on the operating system.
- Always verify generated results before relying on them.

---

⚖️ Disclaimer

This project is intended for educational purposes, software diagnostics, file-format research, and authorized analysis.

Users are responsible for complying with applicable laws, licenses, and permissions.

Automated analysis does not guarantee complete or accurate results.

---

👨‍💻 Credits

Developed by MITTO & Olivia

RBX-Finder / ORC V2

GitHub

https://github.com/MITTO-m4x/obf-db/

---

<p align="center">Analyze • Inspect • Document • Improve</p>

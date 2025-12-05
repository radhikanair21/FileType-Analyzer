# FileType-Analyzer
A simple and effective desktop tool that checks the real type of any file, detects extension spoofing, and verifies file integrity using SHA-256 and this is done without opening or executing the file.
It is useful for spotting hidden malware, phishing attachments, and suspicious downloads.
<img width="1246" height="1007" alt="image" src="https://github.com/user-attachments/assets/9ae1f3b0-121f-4043-a4d9-59ccafd720ea" />

Features:
Detects real file type using magic signatures
Flags mismatches between extension and actual format
Generates SHA-256 hash for integrity and forensic use
Safe static analysis (no execution)
Clean dark-themed Tkinter interface
Exportable text report with all details

Installations:
git clone https://github.com/radhikanair21/FileType-Analyzer
cd FileType-Analyzer
pip install -r requirements.txt
python file_analyzer.py

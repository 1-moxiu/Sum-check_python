# Sum-check_python

A simple Python application to compute and compare file hashes using various algorithms (MD5, SHA-1, SHA-256, SHA-512). The app supports copying computed hashes to the clipboard, exporting them to a file, and comparing the computed hash with a known hash value.

## Features:
- Compute file hashes using MD5, SHA-1, SHA-256, or SHA-512.
- Compare computed hashes with known hashes.
- Copy computed hash to clipboard.
- Export computed hash to a text file.
- Open Moxiu's GitHub page directly from the app.

## Requirements:
To run this script, you'll need the following libraries:
- `tkinter` (for GUI)
- `hashlib` (for hash calculations)
- `pyperclip` (for clipboard functionality)

### Installation:

You can install the required dependencies using `pip`:

```bash
pip install pyperclip
```

Note: `tkinter` and `hashlib` come pre-installed with Python.

## Usage:

1. **Launch the App**: Run the script by executing the Python file.
2. **Select a File**: Click the **"Select File"** button to choose a file from your system.
3. **Choose Hash Algorithm**: Select one of the following hash algorithms: MD5, SHA-1, SHA-256, or SHA-512.
4. **Compute Hash**: Click the **"Compute Hash"** button to calculate the hash of the selected file.
5. **Compare Hashes**: Enter a known hash in the input field and click the **"Compare Hashes"** button to check if the computed hash matches the known hash.
6. **Copy to Clipboard**: Use the **"Copy to Clipboard"** button to copy the computed hash to your clipboard.
7. **Export Hash**: Click the **"Export Hash"** button to save the computed hash to a text file.

### GitHub Link:
- The application includes a clickable link in the bottom right corner that takes you to **My GitHub profile**.

## Author:
Made by **Moxiu**(me) 
On GitHub: [https://github.com/1-moxiu](https://github.com/1-moxiu)

---

### How to run the script:
To run the script, you can execute it directly in the Python environment:

```bash
python file_hash_matcher.py
```

This will open the GUI window where you can interact with the file hashing tool.

## Pre-compiled Program:
You can also download the pre-compiled program from the releases section of the GitHub repository:
### [RELEASES TAB](https://github.com/1-moxiu/Sum-check_python/releases)

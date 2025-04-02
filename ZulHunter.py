#!/usr/bin/env python3
"""
zkhunter.py

A linter for ZKoss (ZUL) files that scans for dangerous patterns such as:
  - Unsafe <zscript> blocks (especially those using Groovy and GroovyShell.evaluate)
  - Unchecked use of Executions.getCurrent().getParameter()
  - Raw <html> components and comboitem content attributes
  - Dynamic <include> src attributes using EL expressions
  - Dangerous client-side calls (e.g., Clients.evalJavaScript)
  - Dynamic component creation (Executions.createComponents or createComponentsDirectly)
  - EL expressions accessing system properties
  - Usage of Label.setRawValue

Usage:
    python zkhunter.py <file or glob pattern>
    Example: python zkhunter.py *.zul
"""

import argparse
import glob
import os
import re
import sys

# Define patterns to scan for
PATTERNS = [
    {
        "name": "Groovy zscript block",
        "regex": r'<zscript[^>]*language\s*=\s*["\']Groovy["\'][^>]*>(.*?)</zscript>',
        "message": "Groovy zscript block detected. Check for dynamic evaluation and potential script injection.",
        "flags": re.DOTALL | re.IGNORECASE,
    },
    {
        "name": "Dynamic GroovyShell.evaluate() call",
        "regex": r'GroovyShell\s*\(\s*\)\s*\.evaluate\s*\(',
        "message": "Dynamic GroovyShell.evaluate() call detected in zscript. Potential for remote code execution.",
        "flags": re.IGNORECASE,
    },
    {
        "name": "Executions.getCurrent().getParameter() usage",
        "regex": r'Executions\.getCurrent\(\)\.getParameter\s*\(',
        "message": "Usage of Executions.getCurrent().getParameter detected. Validate input sources for safety.",
        "flags": re.IGNORECASE,
    },
    {
        "name": "<html> component",
        "regex": r'<html\b',
        "message": "Raw <html> component detected. Ensure proper sanitization if rendering user-provided content.",
        "flags": re.IGNORECASE,
    },
    {
        "name": "Comboitem with content attribute",
        "regex": r'<comboitem\b[^>]*\bcontent\s*=\s*["\'][^"\']*["\']',
        "message": "Comboitem with raw HTML content attribute detected. Validate or sanitize content.",
        "flags": re.IGNORECASE,
    },
    {
        "name": "Dynamic include with EL",
        "regex": r'<include\b[^>]*\bsrc\s*=\s*["\'][^"\']*\$\{[^"\']*\}[^"\']*["\']',
        "message": "Dynamic include src attribute with EL expression detected. Validate allowed pages.",
        "flags": re.IGNORECASE,
    },
    {
        "name": "Clients.evalJavaScript usage",
        "regex": r'Clients\.evalJavaScript\s*\(',
        "message": "Usage of Clients.evalJavaScript detected. Ensure data passed is sanitized.",
        "flags": re.IGNORECASE,
    },
    {
        "name": "Direct component creation",
        "regex": r'Executions\.createComponents(?:Directly)?\s*\(',
        "message": "Dynamic component creation detected (Executions.createComponents or createComponentsDirectly). Validate input parameters.",
        "flags": re.IGNORECASE,
    },
    {
        "name": "EL accessing system properties",
        "regex": r'\$\{[^}]*systemProperties[^}]*\}',
        "message": "EL expression accessing system properties detected. Ensure sensitive data is not exposed.",
        "flags": re.IGNORECASE,
    },
    {
        "name": "Label.setRawValue usage",
        "regex": r'Label\.setRawValue\s*\(',
        "message": "Usage of Label.setRawValue detected. This may output raw HTML; validate content sources.",
        "flags": re.IGNORECASE,
    },
]

def get_line_number(text, pos):
    """Return the line number in text corresponding to the character position pos."""
    return text.count("\n", 0, pos) + 1

def scan_file(file_path):
    """Scan a single file for dangerous patterns and return a list of findings."""
    findings = []
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
    except Exception as e:
        findings.append({"line": 0, "pattern": "File Read Error", "message": str(e)})
        return findings

    for pattern in PATTERNS:
        regex = re.compile(pattern["regex"], flags=pattern["flags"])
        for match in regex.finditer(content):
            line_number = get_line_number(content, match.start())
            findings.append({
                "line": line_number,
                "pattern": pattern["name"],
                "message": pattern["message"]
            })
    return findings

def main():
    parser = argparse.ArgumentParser(
        description="zkhunter.py - A ZKoss (ZUL) security linter for detecting potential vulnerabilities."
    )
    parser.add_argument("paths", nargs="+", help="File or glob pattern(s) to scan (e.g., *.zul)")
    args = parser.parse_args()

    # Expand glob patterns and get unique file list
    files_to_scan = set()
    for pattern in args.paths:
        for file in glob.glob(pattern, recursive=True):
            if os.path.isfile(file):
                files_to_scan.add(file)
    
    if not files_to_scan:
        print("No files found matching the given pattern(s).")
        sys.exit(1)

    overall_findings = {}
    print("Scanning files for potential security issues... (stay curious and keep coding secure!)\n")
    
    for file_path in sorted(files_to_scan):
        findings = scan_file(file_path)
        if findings:
            overall_findings[file_path] = findings

    if not overall_findings:
        print("No dangerous patterns detected. Nice work, but always keep your eyes peeled!")
    else:
        for file_path, issues in overall_findings.items():
            print(f"File: {file_path}")
            for issue in issues:
                print(f"  Line {issue['line']}: [{issue['pattern']}] {issue['message']}")
            print()

if __name__ == "__main__":
    main()


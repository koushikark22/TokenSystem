#!/usr/bin/env python3
"""Append README_ENTERPRISE_SECTION.md to README.md once."""
from pathlib import Path

root = Path(__file__).resolve().parent
readme = root / "README.md"
section = (root / "README_ENTERPRISE_SECTION.md").read_text(encoding="utf-8").strip()
marker = "## License-free enterprise identity security lab"

text = readme.read_text(encoding="utf-8")
if marker in text:
    print("README already contains the enterprise lab section.")
else:
    readme.write_text(text.rstrip() + "\n\n" + section + "\n", encoding="utf-8")
    print("README enterprise lab section appended.")

#!/usr/bin/env python3
"""Marca historias del backlog: mark_story.py <estado> H1.1 H1.2 ...  (estado: done|manual|wip|todo)."""
import re
import sys
from pathlib import Path

ICONS = {"done": "✅", "manual": "🖐", "wip": "🟨", "todo": "⬜"}
path = Path(__file__).resolve().parent.parent / "docs" / "backlog" / "Backlog.md"
icon = ICONS[sys.argv[1]]
text = path.read_text(encoding="utf-8")
for story in sys.argv[2:]:
    pattern = re.compile(rf"^(\| {re.escape(story)} \|.*\| )(⬜|🟨|✅|🖐)( \|)$", re.M)
    text, n = pattern.subn(lambda m: m.group(1) + icon + m.group(3), text)
    if n != 1:
        sys.exit(f"No se encontró la historia {story}")
path.write_text(text, encoding="utf-8")

from __future__ import annotations

import re
from typing import Dict, List, Tuple

BEGIN = re.compile(r"@lock-begin\s+([A-Za-z0-9_.\-]+)")
END = re.compile(r"@lock-end\s+([A-Za-z0-9_.\-]+)")

Norm = Tuple[str, ...]


def _clean(line: str, mode: str) -> str:
    return line.rstrip() if mode == "indent" else line.strip()


def normalize(text: str, mode: str = "ignore") -> Norm:
    """Drop blank lines and trailing whitespace.

    mode "ignore" also strips leading whitespace, so re-indenting is not a change;
    mode "indent" keeps it (for languages where indentation carries meaning).
    """
    return tuple(c for c in (_clean(line, mode) for line in text.splitlines()) if c.strip())


def extract_blocks(text: str, mode: str = "ignore") -> Dict[str, Norm]:
    """Map block id -> normalized content between its markers.

    An unclosed block extends to the end of the file (fail closed).
    """
    content: Dict[str, List[str]] = {}
    open_ids: List[str] = []
    for line in text.splitlines():
        begin = BEGIN.search(line)
        if begin:
            open_ids.append(begin.group(1))
            content.setdefault(begin.group(1), [])
            continue
        end = END.search(line)
        if end:
            if end.group(1) in open_ids:
                open_ids.reverse()
                open_ids.remove(end.group(1))
                open_ids.reverse()
            continue
        cleaned = _clean(line, mode)
        if cleaned.strip():
            for block_id in open_ids:
                content[block_id].append(cleaned)
    return {k: tuple(v) for k, v in content.items()}

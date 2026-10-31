from __future__ import annotations

import re
from typing import Dict, List, Tuple

BEGIN = re.compile(r"@lock-begin\s+([A-Za-z0-9_.\-]+)")
END = re.compile(r"@lock-end\s+([A-Za-z0-9_.\-]+)")

Norm = Tuple[str, ...]


def normalize(text: str) -> Norm:
    """Strip each line and drop blank lines, so whitespace-only edits don't count."""
    return tuple(line.strip() for line in text.splitlines() if line.strip())


def extract_blocks(text: str) -> Dict[str, Norm]:
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
        stripped = line.strip()
        if stripped:
            for block_id in open_ids:
                content[block_id].append(stripped)
    return {k: tuple(v) for k, v in content.items()}

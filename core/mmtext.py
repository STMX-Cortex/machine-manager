# SPDX-License-Identifier: Apache-2.0
"""machine-manager's cleaning of values an agent can choose, for every output (design C-17, C-20). Pure functions.

Values an agent can choose (file, folder and ticket names, call labels, paths below agent folders, text read from such
files) reach alert keys and texts, `mm cleanup` and `mm place`. In any output they show only cleaned: each character
of the Unicode categories in BAD_CATEGORIES (C0 and C1 controls, DEL, the bidi and other format characters, LINE and
PARAGRAPH SEPARATOR) and each `|` (the alert line's ` | do: ` separator) shows as CONTROL_STAND_IN. In plain output and
in an alert's free text such a value shows JSON-quoted unless every character is one of BARE's. machine-manager's own
commands keep their `|`; a command that holds a BAD_CATEGORIES character, or that would have named an agent value
cleaning changes, is withheld.
"""
import json
import re
import shlex
import unicodedata

BAD_CATEGORIES = frozenset(("Cc", "Cf", "Zl", "Zp"))
CONTROL_STAND_IN = "?"  # what is shown in place of each of them (plain ASCII, safe on every terminal)
# The characters a plain `key=value` value (and an id in an alert line's head) may hold bare; anything else, or an
# empty value, is shown JSON-quoted (C-20 (2)).
BARE = re.compile(r"[A-Za-z0-9._/:@+,~-]+")
# The stored command of an alert whose command would have named an agent value that cleaning changes (C-20 (3)):
# never run or shown; outputs show `mm explain KEY` in a line, or command=withheld.
WITHHELD_COMMAND = "(withheld)"


def has_controls(text):
    """text holds a BAD_CATEGORIES character (a command that does is withheld)."""
    return not text.isprintable() and any(unicodedata.category(c) in BAD_CATEGORIES for c in text)


def clean(text):
    """An agent value as outputs show it: each BAD_CATEGORIES character and each `|` as CONTROL_STAND_IN."""
    text = str(text)
    if text.isprintable() and "|" not in text:  # no control, format or separator character, no `|`
        return text
    return "".join(CONTROL_STAND_IN if c == "|" or unicodedata.category(c) in BAD_CATEGORIES else c for c in text)


def clean_obj(o):
    """clean() over every string inside lists and dicts (keys too)."""
    if isinstance(o, str):
        return clean(o)
    if isinstance(o, (list, tuple)):
        return [clean_obj(x) for x in o]
    if isinstance(o, dict):
        return {clean_obj(k) if isinstance(k, str) else k: clean_obj(v) for k, v in o.items()}
    return o


def quoted(value):
    """An agent value inside plain output or an alert's free text: cleaned, and JSON-quoted unless every character is
    one of BARE's (C-20 (2)), so it never reads as words of machine-manager's own."""
    v = clean(value)
    return v if BARE.fullmatch(v) else json.dumps(v)


def command_with(template, *values):
    """machine-manager's command `template % values`, each value shell-quoted; WITHHELD_COMMAND when cleaning changes
    any of the values (an agent value with a replaced character, C-20 (3))."""
    if any(clean(v) != v for v in values):
        return WITHHELD_COMMAND
    return template % tuple(shlex.quote(v) for v in values)

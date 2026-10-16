# SPDX-License-Identifier: Apache-2.0
"""machine-manager's cleaning and masking of text an agent can make, for every output and file (design C-17, C-20 to
C-23). Pure functions; every writer goes through them.

Values an agent can choose (file, folder and ticket names, call labels, paths below agent folders, text read from such
files) reach alert keys and texts, `mm cleanup` and `mm place`. In any output they show only cleaned: each character
of the Unicode categories in BAD_CATEGORIES (C0 and C1 controls, DEL, the bidi and other format characters, LINE and
PARAGRAPH SEPARATOR) and each `|` (the alert line's ` | do: ` separator) shows as CONTROL_STAND_IN. In plain output and
in an alert's free text such a value shows JSON-quoted unless every character is one of BARE's. machine-manager's own
commands keep their `|`; a command that holds a BAD_CATEGORIES character, or that would have named an agent value
cleaning changes, is withheld.
Every regular expression over such text runs on bounded pieces (C-22): the text is split at its line feeds (the only
record end machine-manager's files and parsers know; any other line-breaking character stays inside its line, where
the writers clean it) and each line is cut to TEXT_LINE_MAX characters, with CUT_MARK, first (lines() and cut()).
Each file machine-manager writes holds such text only cleaned (C-23): its own logs (append_line), the evidence
bundle's copies (log_text) and JSON strings (clean_obj). mask() replaces secret-shaped parts; an agent value is
masked before it is quoted, and a text made of own words and quoted values is masked part by part (mask_keep_quotes),
so a mask never takes a closing quote.
"""
import bisect
import json
import math
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

# The longest line any pattern sees (C-22; the profile's text_line_max, set by set_text_line_max at its load): a longer
# line is cut to this many characters and ends with CUT_MARK.
TEXT_LINE_MAX_DEFAULT = 4096
TEXT_LINE_MAX = TEXT_LINE_MAX_DEFAULT
CUT_MARK = "[...cut]"


def set_text_line_max(n):
    """Use n as TEXT_LINE_MAX (the profile's text_line_max)."""
    global TEXT_LINE_MAX
    TEXT_LINE_MAX = int(n)


def cut(line):
    """One line as a pattern may see it: at most TEXT_LINE_MAX characters; a longer line keeps its start and ends with
    CUT_MARK (so a cut line is never cut again)."""
    return line if len(line) <= TEXT_LINE_MAX else line[:TEXT_LINE_MAX - len(CUT_MARK)] + CUT_MARK


def split_lines(text):
    """The records of a text: split at its line feeds only (C-22), as str.splitlines() would give them but for the
    other line-breaking characters (an agent can put them inside a record)."""
    parts = text.split("\n")
    if parts[-1] == "":
        parts.pop()
    return parts


def lines(text):
    """(line, line end) for each line of text split at its line feeds, the line cut (cut); the end is "\n", or "" for
    the last line."""
    pieces = text.split("\n")
    for i, piece in enumerate(pieces):
        if i == len(pieces) - 1 and not piece:
            return  # the text ended with a line feed
        yield cut(piece), "\n" if i < len(pieces) - 1 else ""


def search(rx, text):
    """The first match of rx (a pattern or its text) in one line of text, each line cut (C-22); None when none."""
    rx = re.compile(rx) if isinstance(rx, str) else rx
    for body, _ in lines(text or ""):
        m = rx.search(body)
        if m:
            return m
    return None


def too_long(text):
    """True when a line of text is longer than TEXT_LINE_MAX (search sees only its cut start)."""
    return any(len(line) > TEXT_LINE_MAX for line in (text or "").split("\n"))


def log_text(text, keep=""):
    """A copied text (an agent-writable log) for a file of machine-manager's: split at its line feeds, each line cut
    (cut) and cleaned (clean: C-17's replacement), so every reader sees the same records (C-23). keep: characters
    that stay (a tab-separated log's tab, C-23a)."""
    return "\n".join(clean(cut(line), keep) for line in text.split("\n"))


def has_controls(text):
    """text holds a BAD_CATEGORIES character (a command that does is withheld)."""
    return not text.isprintable() and any(unicodedata.category(c) in BAD_CATEGORIES for c in text)


def clean(text, keep=""):
    """An agent value as outputs show it: each BAD_CATEGORIES character and each `|` as CONTROL_STAND_IN (but the
    characters in keep)."""
    text = str(text)
    if text.isprintable() and "|" not in text:  # no control, format or separator character, no `|`
        return text
    return "".join(c if c in keep else CONTROL_STAND_IN if c == "|" or unicodedata.category(c) in BAD_CATEGORIES
                   else c for c in text)


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
    """An agent value inside plain output or an alert's free text: cleaned and masked (before it is quoted, R5C-4), and
    JSON-quoted unless every character is one of BARE's (C-20 (2)), so it never reads as words of machine-manager's
    own."""
    v = mask(clean(value))
    return v if BARE.fullmatch(v) else json.dumps(v)


def command_with(template, *values):
    """machine-manager's command `template % values`, each value shell-quoted; WITHHELD_COMMAND when cleaning or
    masking changes any of the values (an agent value with a replaced character, C-20 (3); a secret, R5C-4)."""
    if any(clean(v) != v or mask(v) != v for v in values):
        return WITHHELD_COMMAND
    return template % tuple(shlex.quote(v) for v in values)


# --------------------------------------------------------------------------------------------- masking

_SECRET_RES = [
    re.compile(r"(?i)\b([A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|PASSPHRASE|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|_KEY|CREDENTIALS?|AUTH))(\s*[=:]\s*)(\"[^\"]*\"|'[^']*'|\S+)"),
    re.compile(r"(?i)(--(?:token|password|passphrase|secret|api-key|key|auth)(?:=|\s+))(\S+)"),
    re.compile(r"(?i)\b(bearer|basic|token)(\s+)([A-Za-z0-9._~+/=-]{8,})"),
    # a JWT starts a run of its characters (not after a `-` either): one try per run, so a run of `eyJ-` costs time
    # linear in it (R5C-1), on top of C-22's cut
    re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{16,}|xox[abpr]-[A-Za-z0-9-]{10,}"
               r"|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{30,}|(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,})"),
    None,  # private key blocks: _KEY_BEGIN and _KEY_END, line by line in mask()
    re.compile(r"(?<![A-Za-z0-9+_=-])[A-Za-z0-9+_=-]{32,}(?![A-Za-z0-9+_=-])"),
    # a URL's password holds no raw `/` (RFC 3986 userinfo): each try stops at the next `://`, so a run of `://a:`
    # costs time linear in it (R5C-1), on top of C-22's cut
    re.compile(r"(?i)(://[^/\s:@]+:)([^@\s/]+)(@)"),
]
_KEY_BEGIN = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
_KEY_END = re.compile(r"-----END [A-Z ]*PRIVATE KEY-----")
KEY_MARK = "***PRIVATE KEY***"

# A path, whose segments the long-random-word rule keeps (mask's doc: "Paths ... are kept"): a word that starts with
# /, ~/, ./ or ../ at the start of the text or after white space, a quote, =, (, [ or ,; it runs to white space or a
# quote. A word starting with :// (a URL) is no path: its parts stay masked as before.
_PATH_RE = re.compile(r"""(?:^|(?<=[\s"'=(\[,]))(?:~|\.\.?)?/[^\s"']*""")
# One double-quoted part of a text (a value quoted() made, or a repr): mask_keep_quotes holds it as one _HOLE while
# the rules run over the line, then masks it inside its quotes.
_QUOTED_PART = re.compile(r'"(?:[^"\\]|\\.)*"')
# A held quoted part: NUL, its number, NUL. No rule's value stops inside one (none holds white space or a rule's
# delimiter), so a rule takes a held part whole or not at all. A line that holds a NUL itself is masked as by mask().
_HOLE = "\x00%d\x00"
_HOLE_RE = re.compile("\x00([0-9]+)\x00")


def _random(w):
    """A long word that looks random: letters and digits mixed, high entropy (hex digests and UUIDs stay)."""
    if not (re.search(r"[0-9]", w) and re.search(r"[A-Za-z]", w)) or re.fullmatch(r"[0-9a-fA-F-]+", w):
        return False
    n = len(w)
    ent = -sum(c / n * math.log2(c / n) for c in (w.count(ch) for ch in set(w)))
    return ent >= 4.2


def _mask_line(t):
    """mask()'s rules on one cut line (no private key block)."""
    t = _SECRET_RES[0].sub(lambda m: m.group(1) + m.group(2) + "***", t)
    t = _SECRET_RES[1].sub(lambda m: m.group(1) + "***", t)
    t = _SECRET_RES[2].sub(lambda m: m.group(1) + m.group(2) + "***", t)
    t = _SECRET_RES[3].sub("***", t)
    t = _SECRET_RES[6].sub(lambda m: m.group(1) + "***" + m.group(3), t)
    paths = [m.span() for m in _PATH_RE.finditer(t)]  # in text order, never overlapping
    starts = [a for a, _ in paths]

    def word(m):
        i = bisect.bisect_right(starts, m.start()) - 1  # the last path starting at or before the word (C-21: no scan)
        if i >= 0 and m.end() <= paths[i][1]:
            return m.group(0)  # a segment of a path
        return "***" if _random(m.group(0)) else m.group(0)
    return _SECRET_RES[5].sub(word, t)


def _mask_line_keep_quotes(t):
    """_mask_line() with each quoted part held whole (_HOLE): a rule that takes a value takes its whole quoted part,
    quotes and all; each part left is masked inside its quotes. So no rule ever takes one quote of a pair."""
    if "\x00" in t:
        return _mask_line(t)
    held, parts, pos = [], [], 0
    while True:  # each quote tried once (C-21): when one finds no closing quote, no later one does (escapes line up)
        i = t.find('"', pos)
        m = _QUOTED_PART.match(t, i) if i >= 0 else None
        if not m:
            break
        held.append(m.group(0)[1:-1])
        parts += [t[pos:i], _HOLE % (len(held) - 1)]
        pos = m.end()
    t = _mask_line("".join(parts) + t[pos:])
    return _HOLE_RE.sub(lambda m: '"' + _mask_line(held[int(m.group(1))]) + '"', t)


def mask(text, one_line=_mask_line):
    """Secret-shaped parts of a text replaced by ***: KEY=value pairs with secret names, --token style flags, bearer
    strings, known token prefixes, private key blocks (from BEGIN to END, as KEY_MARK), passwords in URLs and long
    random words (32+ chars, letters and digits, high entropy). Paths (_PATH_RE: the long-random-word rule never cuts
    into one), hex digests and UUIDs are kept. The rules run line by line on cut lines (C-22): a line longer than
    TEXT_LINE_MAX keeps its first TEXT_LINE_MAX characters and CUT_MARK. one_line: the rules for one line's text."""
    if not isinstance(text, str) or not text:
        return text
    out, in_key = [], False
    for body, end in lines(text):
        if in_key:  # inside a private key block: dropped up to its END
            m = _KEY_END.search(body)
            if not m:
                continue
            in_key, body = False, body[m.end():]
            out.append(one_line(body) + end)
            continue
        b = _KEY_BEGIN.search(body)
        if b:
            e = _KEY_END.search(body, b.end())
            if e is None:
                out.append(one_line(body[:b.start()]) + KEY_MARK)
                in_key = True
                continue
            out.append(one_line(body[:b.start()]) + KEY_MARK + one_line(body[e.end():]) + end)
            continue
        out.append(one_line(body) + end)
    return "".join(out)


def mask_keep_quotes(text):
    """mask() of a text that holds quoted values (alert texts, log lines, copies): it masks what mask() masks, and a
    rule takes a quoted part whole or not at all, so a closing quote never goes and a later value never shows
    unquoted (R5C-4). Each quoted part left is masked inside its quotes."""
    return mask(text, _mask_line_keep_quotes)


def mask_obj(o):
    """mask_keep_quotes() over every string inside lists and dicts (keys too)."""
    if isinstance(o, str):
        return mask_keep_quotes(o)
    if isinstance(o, list):
        return [mask_obj(x) for x in o]
    if isinstance(o, tuple):
        return tuple(mask_obj(x) for x in o)
    if isinstance(o, dict):
        return {mask_obj(k) if isinstance(k, str) else k: mask_obj(v) for k, v in o.items()}
    return o

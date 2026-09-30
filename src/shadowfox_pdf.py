"""Minimal, dependency-free PDF report writer shared by ShadowFox tools.

No third-party packages: builds a PDF 1.4 file by hand (objects, xref, trailer)
using the 14 standard PDF fonts (Helvetica/Courier families), so no font
embedding is needed. Good enough for paginated, text-heavy audit reports;
not a general-purpose PDF library.
"""
from __future__ import annotations

import textwrap
import zlib
from datetime import datetime

PAGE_W = 595.27  # A4
PAGE_H = 841.89
MARGIN = 50.0
CONTENT_W = PAGE_W - 2 * MARGIN
FOOTER_Y = MARGIN - 12

_FONT_WIDTH_FACTOR = {
    "Helvetica": 0.52,
    "Helvetica-Bold": 0.56,
    "Courier": 0.60,
    "Courier-Bold": 0.60,
}

# Brand palette (matches STYLE_GUIDE.md HTML colour tokens)
BLACK = (0.07, 0.07, 0.07)
GREY = (0.42, 0.46, 0.5)
BORDER = (0.75, 0.78, 0.8)
NAVY = (0.05, 0.09, 0.13)
GREEN = (0.19, 0.49, 0.20)   # PASS
RED = (0.78, 0.16, 0.16)     # FAIL
ORANGE = (0.94, 0.41, 0.0)   # WARN
BLUE = (0.08, 0.40, 0.75)    # INFO
DEEP_RED = (0.55, 0.0, 0.0)  # CRIT


# WinAnsiEncoding (cp1252) can't represent these; ShadowFox terminal output
# uses them freely (box-drawing, arrows, block bars), so map to ASCII first.
_ASCII_FALLBACK = {
    "→": "->", "←": "<-", "↔": "<->",
    "►": ">", "◄": "<", "▲": "^", "▼": "v",
    "█": "#", "░": ".", "▒": "#", "▓": "#",
    "•": "*", "…": "...",
    "─": "-", "│": "|", "═": "=", "║": "|",
    "╔": "+", "╗": "+", "╚": "+", "╝": "+",
    "╭": "+", "╮": "+", "╰": "+", "╯": "+",
}


def _sanitize(text: str) -> str:
    for char, repl in _ASCII_FALLBACK.items():
        if char in text:
            text = text.replace(char, repl)
    return text


def _escape(text: str) -> str:
    text = _sanitize(text)
    return text.replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)")


def _max_chars(font: str, size: float) -> int:
    factor = _FONT_WIDTH_FACTOR[font]
    return max(10, int(CONTENT_W / (factor * size)))


class PDFReport:
    """Builds one paginated PDF report. Call save() once at the end."""

    def __init__(self, tool: str, title: str, subtitle: str = ""):
        self.tool = tool
        self.title = title
        self.subtitle = subtitle
        self._pages: list[str] = []
        self._cur: list[str] = []
        self._y = PAGE_H - MARGIN
        self._start_page()

    # -- page management ------------------------------------------------

    def _start_page(self) -> None:
        self._cur = []
        self._y = PAGE_H - MARGIN
        self._raw_rule(MARGIN, self._y, PAGE_W - MARGIN, BORDER, 0.75)
        self._raw_text(MARGIN, self._y + 6, self.tool, "Helvetica-Bold", 9, GREY)
        self._y -= 22

    def _finish_page(self) -> None:
        page_no = len(self._pages) + 1
        self._raw_rule(MARGIN, FOOTER_Y + 12, PAGE_W - MARGIN, BORDER, 0.5)
        stamp = datetime.now().strftime("%Y-%m-%d %H:%M")
        self._raw_text(MARGIN, FOOTER_Y, f"Generated {stamp} - shadowfox.se",
                        "Helvetica", 8, GREY)
        self._raw_text(PAGE_W - MARGIN - 40, FOOTER_Y, f"Page {page_no}",
                        "Helvetica", 8, GREY)
        self._pages.append("\n".join(self._cur))

    def _ensure_space(self, needed: float) -> None:
        if self._y - needed < MARGIN + 24:
            self._finish_page()
            self._start_page()

    def page_break(self) -> None:
        self._finish_page()
        self._start_page()

    # -- low-level content stream ops -----------------------------------

    def _raw_text(self, x: float, y: float, text: str, font: str, size: float,
                   color: tuple[float, float, float]) -> None:
        r, g, b = color
        self._cur.append(
            f"BT /{font} {size:.1f} Tf {r:.3f} {g:.3f} {b:.3f} rg "
            f"{x:.2f} {y:.2f} Td ({_escape(text)}) Tj ET"
        )

    def _raw_rule(self, x0: float, y: float, x1: float,
                   color: tuple[float, float, float], weight: float = 1.0) -> None:
        r, g, b = color
        self._cur.append(
            f"{r:.3f} {g:.3f} {b:.3f} rg {x0:.2f} {y - weight / 2:.2f} "
            f"{x1 - x0:.2f} {weight:.2f} re f"
        )

    def _raw_box(self, x: float, y: float, w: float, h: float,
                  color: tuple[float, float, float]) -> None:
        r, g, b = color
        self._cur.append(f"{r:.3f} {g:.3f} {b:.3f} rg {x:.2f} {y:.2f} {w:.2f} {h:.2f} re f")

    # -- public drawing API -----------------------------------------------

    def spacer(self, h: float = 8.0) -> None:
        self._y -= h

    def rule(self, color: tuple[float, float, float] = BORDER) -> None:
        self._ensure_space(10)
        self._raw_rule(MARGIN, self._y, PAGE_W - MARGIN, color, 0.75)
        self._y -= 10

    def heading(self, text: str, size: float = 18,
                color: tuple[float, float, float] = NAVY) -> None:
        self._ensure_space(size + 10)
        self._raw_text(MARGIN, self._y, text, "Helvetica-Bold", size, color)
        self._y -= size + 8

    def subheading(self, text: str, size: float = 11,
                    color: tuple[float, float, float] = GREY) -> None:
        self._ensure_space(size + 8)
        self._raw_text(MARGIN, self._y, text, "Helvetica-Bold", size, color)
        self._y -= size + 6

    def text(self, text: str, size: float = 10, bold: bool = False,
              mono: bool = False, color: tuple[float, float, float] = BLACK,
              indent: float = 0.0) -> None:
        font = ("Courier-Bold" if bold else "Courier") if mono else \
               ("Helvetica-Bold" if bold else "Helvetica")
        width = CONTENT_W - indent
        factor = _FONT_WIDTH_FACTOR[font]
        max_chars = max(10, int(width / (factor * size)))
        lines = textwrap.wrap(text, max_chars) or [""]
        line_h = size * 1.4
        for line in lines:
            self._ensure_space(line_h)
            self._raw_text(MARGIN + indent, self._y, line, font, size, color)
            self._y -= line_h

    def severity_line(self, tag: str, label: str, detail: str,
                       color: tuple[float, float, float]) -> None:
        """Renders '[TAG]  Label - detail', tag coloured, wrapped like the CLI."""
        self._ensure_space(14)
        self._raw_text(MARGIN, self._y, f"[{tag}]", "Courier-Bold", 9, color)
        rest = f"{label} — {detail}" if detail else label
        max_chars = _max_chars("Helvetica", 9.5) - 12
        lines = textwrap.wrap(rest, max(10, max_chars)) or [""]
        self._raw_text(MARGIN + 62, self._y, lines[0], "Helvetica", 9.5, BLACK)
        self._y -= 13
        for cont in lines[1:]:
            self._ensure_space(13)
            self._raw_text(MARGIN + 62, self._y, cont, "Helvetica", 9.5, BLACK)
            self._y -= 13

    def kv_bar(self, label: str, value: int, max_value: int,
               count_text: str, color: tuple[float, float, float] = BLUE) -> None:
        """One row of a bar chart: 'label   count_text  [====   ]'."""
        self._ensure_space(16)
        self._raw_text(MARGIN, self._y, label, "Courier", 9.5, BLACK)
        self._raw_text(MARGIN + 160, self._y, count_text, "Helvetica", 9, GREY)
        bar_x = MARGIN + 230
        bar_w = PAGE_W - MARGIN - bar_x
        frac = 0.0 if max_value <= 0 else max(0.0, min(1.0, value / max_value))
        self._raw_box(bar_x, self._y - 2, bar_w, 8, BORDER)
        if frac > 0:
            self._raw_box(bar_x, self._y - 2, bar_w * frac, 8, color)
        self._y -= 16

    def score_bar(self, value: int, band: str,
                   color: tuple[float, float, float]) -> None:
        """Big 0-100 score bar used by Auditor (grade) / Mapper (risk score)."""
        self._ensure_space(30)
        bar_w = CONTENT_W - 90
        frac = max(0.0, min(1.0, value / 100))
        self._raw_box(MARGIN, self._y - 14, bar_w, 16, BORDER)
        if frac > 0:
            self._raw_box(MARGIN, self._y - 14, bar_w * frac, 16, color)
        self._raw_text(MARGIN + bar_w + 10, self._y - 10, f"{value}/100 [{band}]",
                        "Helvetica-Bold", 11, color)
        self._y -= 30

    # -- assembly ---------------------------------------------------------

    def save(self, path: str) -> None:
        self._finish_page()

        objects: list[bytes] = []

        def add_obj(body: bytes) -> int:
            objects.append(body)
            return len(objects)  # 1-based object number

        font_objs = {}
        for name in ("Helvetica", "Helvetica-Bold", "Courier", "Courier-Bold"):
            num = add_obj(
                f"<< /Type /Font /Subtype /Type1 /BaseFont /{name} "
                f"/Encoding /WinAnsiEncoding >>".encode("latin-1")
            )
            font_objs[name] = num

        resources = (
            "<< /Font << " +
            " ".join(f"/{n} {i} 0 R" for n, i in font_objs.items()) +
            " >> >>"
        ).encode("latin-1")

        content_nums = []
        for page_stream in self._pages:
            compressed = zlib.compress(page_stream.encode("cp1252", "replace"))
            cnum = add_obj(
                (f"<< /Length {len(compressed)} /Filter /FlateDecode >>\nstream\n")
                .encode("latin-1") + compressed + b"\nendstream"
            )
            content_nums.append(cnum)

        pages_obj_num = add_obj(b"")  # placeholder, patched below

        page_nums = [add_obj(b"") for _ in content_nums]  # placeholders, patched below

        kids = " ".join(f"{n} 0 R" for n in page_nums)
        objects[pages_obj_num - 1] = (
            f"<< /Type /Pages /Kids [{kids}] /Count {len(page_nums)} >>"
        ).encode("latin-1")

        for i, (pnum, cnum) in enumerate(zip(page_nums, content_nums)):
            objects[pnum - 1] = (
                f"<< /Type /Page /Parent {pages_obj_num} 0 R "
                f"/MediaBox [0 0 {PAGE_W:.2f} {PAGE_H:.2f}] "
                f"/Resources {resources.decode('latin-1')} "
                f"/Contents {cnum} 0 R >>"
            ).encode("latin-1")

        catalog_num = add_obj(
            f"<< /Type /Catalog /Pages {pages_obj_num} 0 R >>".encode("latin-1")
        )

        # -- write file --------------------------------------------------
        out = [b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"]
        offsets = [0]
        pos = len(out[0])
        for i, body in enumerate(objects, start=1):
            header = f"{i} 0 obj\n".encode("latin-1")
            footer = b"\nendobj\n"
            chunk = header + body + footer
            offsets.append(pos)
            out.append(chunk)
            pos += len(chunk)

        xref_start = pos
        xref = [f"xref\n0 {len(objects) + 1}\n".encode("latin-1"),
                b"0000000000 65535 f \n"]
        for off in offsets[1:]:
            xref.append(f"{off:010d} 00000 n \n".encode("latin-1"))
        trailer = (
            f"trailer\n<< /Size {len(objects) + 1} /Root {catalog_num} 0 R >>\n"
            f"startxref\n{xref_start}\n%%EOF"
        ).encode("latin-1")

        with open(path, "wb") as f:
            for chunk in out:
                f.write(chunk)
            for chunk in xref:
                f.write(chunk)
            f.write(trailer)

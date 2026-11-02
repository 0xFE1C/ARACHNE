"""The accessibility audit: every screen, every state, against WCAG 2.2 AA (REQ-UIX-007).

``.spec/06-ui-ux.md`` §8.1 asks for "Axe (or equivalent) … over every screen in CI", and
§8.2 lists the success criteria automation cannot reach. This module is the automated half, and
it is deliberately a **DOM audit with an explicit rule table** rather than a browser: the test
suite runs on a machine with no browser, and a gate that can only run where a browser is
installed is a gate that gets skipped. ``python -m arachne.api.a11y`` renders all 14 screens in
every applicable state (68 documents), parses each one into a small element tree, and applies:

===========================  ==========================================================
rule                         what it is (the axe rule it mirrors)
===========================  ==========================================================
``document-lang``            ``html-has-lang`` / ``html-lang-valid`` (3.1.1)
``document-title``           ``document-title`` (2.4.2)
``duplicate-id``             ``duplicate-id`` / ``duplicate-id-aria`` (4.1.1)
``aria-reference-valid``     every IDREF an ``aria-*`` attribute or a ``<label for>`` names
                             resolves (``aria-valid-attr-value``)
``aria-valid-attr``          every ``aria-*`` attribute is a real one (``aria-valid-attr``)
``accessible-name``          ``button-name`` / ``link-name`` / ``input-button-name`` / ``label``
                             / ``select-name`` / ``image-alt`` / ``aria-required-attr`` (4.1.2)
``landmark-one-main``        one ``<main>``; a second ``<nav>``/``<header>`` is labelled
                             (``landmark-one-main``, ``landmark-unique``)
``heading-order``            no skipped level, exactly one ``<h1>`` (``heading-order``,
                             ``page-has-heading-one``)
``tabindex-positive``        no ``tabindex`` above 0 (``tabindex``, 2.4.3)
``aria-hidden-focus``        nothing focusable inside ``aria-hidden="true"``
                             (``aria-hidden-focus``)
``nested-interactive``       no interactive element inside another (``nested-interactive``)
``modal-labelled``           every ``<dialog>`` has an accessible name and a close control
``focus-order``              header controls precede main-content controls (2.4.3)
``redundant-entry``          a form does not ask for one field twice (3.3.7)
``consistent-help``          the help affordance is in the same place on every screen (3.2.6)
``accessible-auth``          no paste/copy handler, no ``autocomplete="off"`` on the credential
                             field (3.3.8)
``viewport``                 the viewport does not fix a width or forbid zoom (1.4.4, 1.4.10)
``focus-visible``            a focus ring from a token, for every element that removes one (2.4.7)
``target-size``              the control minimum comes from ``--target-min`` and is ≥ 24 CSS px
                             (2.5.8)
``reflow``                   the layout can reflow to 320 CSS px (1.4.10)
``text-spacing``             no ``!important``, so a spacing override can win (1.4.12)
===========================  ==========================================================

What this cannot do, stated rather than implied: a rule that needs layout (measured target
size, measured reflow, computed contrast) needs a browser. Contrast is covered numerically for
every token pair by :mod:`arachne.api.tokens` in both themes; target size and reflow are covered
structurally here and recorded as measured rows in the WP-06 handoff. ``--tab-order`` prints the
keyboard order per screen, which is the evidence for the 2.1.1 / 2.4.3 rows.

Usage::

    python -m arachne.api.a11y               # audit every screen and state; exit 1 on a violation
    python -m arachne.api.a11y --tab-order   # print the keyboard order per screen
    python -m arachne.api.a11y --self-test   # prove every DOM rule fires on planted markup
"""

from __future__ import annotations

import argparse
import itertools
import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from html.parser import HTMLParser
from importlib.resources import files
from pathlib import Path
from typing import Any, Final

__all__ = ["Element", "Violation", "audit", "main", "parse", "tab_order"]

#: Elements that never have children (the HTML void elements).
_VOID: Final[frozenset[str]] = frozenset(
    {
        "area",
        "base",
        "br",
        "col",
        "embed",
        "hr",
        "img",
        "input",
        "link",
        "meta",
        "param",
        "source",
        "track",
        "wbr",
    }
)

#: Elements that can take keyboard focus without a `tabindex`.
_FOCUSABLE: Final[frozenset[str]] = frozenset({"a", "button", "input", "select", "textarea"})

#: `<input>` types that are not user-editable fields and therefore need no label.
_UNLABELLED_INPUT_TYPES: Final[frozenset[str]] = frozenset(
    {"hidden", "submit", "button", "reset", "image"}
)

#: The `aria-*` attributes this interface may use (WAI-ARIA 1.2, the subset that applies).
_KNOWN_ARIA: Final[frozenset[str]] = frozenset(
    {
        "aria-atomic",
        "aria-busy",
        "aria-checked",
        "aria-controls",
        "aria-current",
        "aria-describedby",
        "aria-description",
        "aria-disabled",
        "aria-expanded",
        "aria-haspopup",
        "aria-hidden",
        "aria-label",
        "aria-labelledby",
        "aria-live",
        "aria-modal",
        "aria-owns",
        "aria-placeholder",
        "aria-pressed",
        "aria-readonly",
        "aria-required",
        "aria-selected",
        "aria-sort",
        "aria-valuemax",
        "aria-valuemin",
        "aria-valuenow",
        "aria-valuetext",
    }
)

#: Attributes that carry one or more IDREFs.
_IDREF_ATTRIBUTES: Final[tuple[str, ...]] = (
    "aria-activedescendant",
    "aria-controls",
    "aria-describedby",
    "aria-labelledby",
    "aria-owns",
    "for",
    "headers",
    "list",
)

#: The minimum pointer target WCAG 2.5.8 asks for, in CSS pixels.
_TARGET_MIN_PX: Final = 24

_CSS_COMMENT: Final = re.compile(r"/\*.*?\*/", re.DOTALL)
_DECLARATION: Final = re.compile(r"([a-z-]+)\s*:\s*([^;{}]+)", re.IGNORECASE)


@dataclass(frozen=True, slots=True)
class Violation:
    """One audit finding, located like a compiler diagnostic: screen, state, rule, detail."""

    screen: str
    state: str
    rule: str
    detail: str

    def __str__(self) -> str:
        return f"{self.screen}[{self.state}] {self.rule}: {self.detail}"


# --------------------------------------------------------------------------- the element tree
@dataclass(slots=True)
class Element:
    """One element of a parsed document, with its children in document order."""

    tag: str
    attrs: dict[str, str] = field(default_factory=dict)
    children: list[Element | str] = field(default_factory=list)
    parent: Element | None = None

    def walk(self) -> Iterator[Element]:
        """This element and every descendant, in document order."""
        yield self
        for child in self.children:
            if isinstance(child, Element):
                yield from child.walk()

    def text(self) -> str:
        """Every character a reader sees inside this element."""
        parts: list[str] = []
        for child in self.children:
            parts.append(child if isinstance(child, str) else child.text())
        return "".join(parts)

    def find_all(self, *tags: str) -> list[Element]:
        return [node for node in self.walk() if node.tag in tags]

    def closest(self, *tags: str) -> Element | None:
        node = self.parent
        while node is not None:
            if node.tag in tags:
                return node
            node = node.parent
        return None


class _Builder(HTMLParser):
    """A forgiving builder: a mismatched end tag closes the nearest open element of that name."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.root = Element("#document")
        self.stack: list[Element] = [self.root]
        self.unbalanced: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        element = Element(
            tag, {name: (value if value is not None else "") for name, value in attrs}
        )
        element.parent = self.stack[-1]
        self.stack[-1].children.append(element)
        if tag not in _VOID:
            self.stack.append(element)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)
        if tag not in _VOID:
            self.stack.pop()

    def handle_endtag(self, tag: str) -> None:
        for index in range(len(self.stack) - 1, 0, -1):
            if self.stack[index].tag == tag:
                del self.stack[index:]
                return
        self.unbalanced.append(tag)

    def handle_data(self, data: str) -> None:
        self.stack[-1].children.append(data)


def parse(markup: str) -> tuple[Element, list[str]]:
    """Parse a rendered page into a tree, plus the end tags that matched nothing."""
    builder = _Builder()
    builder.feed(markup)
    builder.close()
    return builder.root, builder.unbalanced


# --------------------------------------------------------------------------- names and focus
def _by_id(root: Element) -> dict[str, Element]:
    found: dict[str, Element] = {}
    for node in root.walk():
        if node.attrs.get("id"):
            found.setdefault(node.attrs["id"], node)
    return found


def accessible_name(node: Element, identifiers: dict[str, Element]) -> str:
    """The name a screen reader would announce for ``node`` (a deliberate simplification).

    The ACCNAME algorithm in full is a graph walk; this covers the orders this interface uses:
    ``aria-labelledby``, then ``aria-label``, then a ``<label for>``, then an ancestor
    ``<label>``, then the element's own text (or ``alt``/``value``), then ``title``.
    """
    labelled = node.attrs.get("aria-labelledby", "")
    if labelled:
        parts = [identifiers[ref].text() for ref in labelled.split() if ref in identifiers]
        if any(part.strip() for part in parts):
            return " ".join(part.strip() for part in parts if part.strip())
    if node.attrs.get("aria-label", "").strip():
        return node.attrs["aria-label"].strip()
    identifier = node.attrs.get("id")
    if identifier:
        for candidate in node.find_all("label") + (
            node.parent.find_all("label") if node.parent else []
        ):
            if candidate.attrs.get("for") == identifier:
                return candidate.text().strip()
    ancestor_label = node.closest("label")
    if ancestor_label is not None and ancestor_label.text().strip():
        return ancestor_label.text().strip()
    if node.tag == "img":
        return node.attrs.get("alt", "").strip()
    if node.tag == "input" and node.attrs.get("type") in {"submit", "button", "reset"}:
        return node.attrs.get("value", "").strip()
    text = node.text().strip()
    if text:
        return text
    return node.attrs.get("title", "").strip()


def _explicit_name(node: Element, identifiers: dict[str, Element]) -> str:
    """The name an element *declares* (``aria-label``/``aria-labelledby``/``title``).

    A landmark is the case where the fallback matters: ``<nav>``'s content is not its name, so
    a landmark check that accepted "the text inside it" would pass on every page and test
    nothing. This is the stricter question, and the one ``landmark-unique`` asks.
    """
    labelled = node.attrs.get("aria-labelledby", "")
    if labelled:
        parts = [identifiers[ref].text() for ref in labelled.split() if ref in identifiers]
        if any(part.strip() for part in parts):
            return " ".join(part.strip() for part in parts if part.strip())
    return (node.attrs.get("aria-label") or node.attrs.get("title") or "").strip()


def _is_focusable(node: Element) -> bool:
    if node.attrs.get("tabindex") is not None:
        return int(node.attrs.get("tabindex") or "0") >= 0
    if node.tag in _FOCUSABLE:
        return node.attrs.get("disabled") is None
    return False


def tab_order(root: Element) -> list[str]:
    """The keyboard order: every focusable element, in document order, as ``tag[name]``."""
    order: list[str] = []
    for node in root.walk():
        if not _is_focusable(node):
            continue
        name = (
            node.attrs.get("aria-label") or node.attrs.get("name") or node.attrs.get("href") or ""
        )
        order.append(f"{node.tag}[{name}]" if name else node.tag)
    return order


# --------------------------------------------------------------------------- the DOM rules
def _document_rules(page: Element) -> list[str]:
    problems: list[str] = []
    html = next((node for node in page.walk() if node.tag == "html"), None)
    if html is None or not html.attrs.get("lang", "").strip():
        problems.append("document-lang: <html> has no lang attribute (3.1.1)")
    elif not re.fullmatch(r"[A-Za-z]{2,3}(-[A-Za-z0-9]+)*", html.attrs["lang"].strip()):
        problems.append(f"document-lang: {html.attrs['lang']!r} is not a language tag (3.1.1)")
    titles = [node for node in page.walk() if node.tag == "title"]
    if len(titles) != 1 or not titles[0].text().strip():
        problems.append("document-title: a page needs exactly one non-empty <title> (2.4.2)")
    viewports = [node for node in page.walk() if node.tag == "meta"]
    viewport = next(
        (node for node in viewports if node.attrs.get("name", "").lower() == "viewport"), None
    )
    if viewport is None:
        problems.append("viewport: no viewport meta (1.4.10)")
    else:
        content = viewport.attrs.get("content", "").lower()
        if "width=device-width" not in content:
            problems.append(f"viewport: {content!r} does not follow the device width (1.4.10)")
        if re.search(r"user-scalable\s*=\s*no|maximum-scale\s*=\s*1\b", content):
            problems.append(f"viewport: {content!r} forbids zoom (1.4.4)")
    return problems


def _structural_rules(page: Element) -> list[str]:
    problems: list[str] = []
    identifiers: dict[str, Element] = {}
    for node in page.walk():
        identifier = node.attrs.get("id")
        if not identifier:
            continue
        if identifier in identifiers:
            problems.append(f"duplicate-id: {identifier!r} appears twice (4.1.1)")
        identifiers.setdefault(identifier, node)

    for node in page.walk():
        for attribute in _IDREF_ATTRIBUTES:
            value = node.attrs.get(attribute)
            if not value:
                continue
            for reference in value.split():
                if reference not in identifiers:
                    problems.append(
                        f"aria-reference-valid: <{node.tag} {attribute}={reference!r}> names no "
                        f"element (4.1.1)"
                    )
        for attribute in node.attrs:
            if attribute.startswith("aria-") and attribute not in _KNOWN_ARIA:
                problems.append(f"aria-valid-attr: {attribute!r} is not a known ARIA attribute")

    headings = [node for node in page.walk() if re.fullmatch(r"h[1-6]", node.tag)]
    levels = [int(node.tag[1]) for node in headings]
    if levels.count(1) != 1:
        problems.append(f"heading-order: {levels.count(1)} <h1> elements (2.4.6)")
    for previous, following in itertools.pairwise(levels):
        if following > previous + 1:
            problems.append(f"heading-order: h{previous} is followed by h{following} (1.3.1)")
            break

    mains = page.find_all("main")
    if len(mains) != 1:
        problems.append(f"landmark-one-main: {len(mains)} <main> landmarks (1.3.6)")
    for tag, label in (("nav", "navigation"), ("header", "banner"), ("footer", "contentinfo")):
        landmarks = page.find_all(tag)
        if len(landmarks) > 1 and any(not _explicit_name(node, identifiers) for node in landmarks):
            problems.append(
                f"landmark-one-main: more than one <{tag}> and one is unnamed ({label})"
            )

    for node in page.walk():
        if not _is_focusable(node):
            continue
        for ancestor in (node, *iter(_ancestors(node))):
            if ancestor.attrs.get("aria-hidden", "").lower() == "true":
                problems.append(
                    f"aria-hidden-focus: <{node.tag}> is focusable inside an aria-hidden subtree"
                )
                break
        index = node.attrs.get("tabindex")
        if index is not None and index.lstrip("+").isdigit() and int(index) > 0:
            problems.append(
                f"tabindex-positive: <{node.tag} tabindex={index}> reorders focus (2.4.3)"
            )

    for node in page.walk():
        if node.tag not in _FOCUSABLE:
            continue
        if node.closest("a", "button") is not None:
            problems.append(
                f"nested-interactive: <{node.tag}> is inside a link or a button (4.1.2)"
            )
    return problems


def _ancestors(node: Element) -> Iterator[Element]:
    parent = node.parent
    while parent is not None:
        yield parent
        parent = parent.parent


def _name_rules(page: Element) -> list[str]:
    problems: list[str] = []
    identifiers = _by_id(page)
    for node in page.walk():
        named = node.tag in {"button", "a", "select", "textarea", "summary", "img"}
        if node.tag == "input":
            named = node.attrs.get("type", "text").lower() not in {"hidden"}
        if not named:
            continue
        if (
            node.tag == "input"
            and node.attrs.get("type", "text").lower() in _UNLABELLED_INPUT_TYPES
        ):
            if node.attrs.get("type") == "image" and not accessible_name(node, identifiers):
                problems.append("accessible-name: <input type=image> has no alt (4.1.2)")
            continue
        if node.tag == "img" and node.attrs.get("alt") is not None:
            continue  # an empty alt is the correct spelling of a decorative image
        if not accessible_name(node, identifiers):
            problems.append(f"accessible-name: <{node.tag}> has no accessible name (4.1.2)")
    for node in page.walk():
        if (
            node.tag == "svg"
            and node.attrs.get("role") == "img"
            and not accessible_name(node, identifiers)
        ):
            problems.append("accessible-name: <svg role=img> has no accessible name (1.1.1)")
    return problems


def _interaction_rules(page: Element) -> list[str]:
    problems: list[str] = []
    identifiers = _by_id(page)
    for dialog in page.find_all("dialog"):
        if not accessible_name(dialog, identifiers):
            problems.append("modal-labelled: <dialog> has no accessible name (4.1.2)")
        if not dialog.find_all("button"):
            problems.append("modal-labelled: <dialog> has no control to close it (2.1.2)")

    # 2.4.3: the chrome is read before the content, so its controls come first in the tab order.
    if any(node.tag == "header" for node in page.walk()) and any(
        node.tag == "main" for node in page.walk()
    ):
        order = [node for node in page.walk() if _is_focusable(node)]
        header_at = [
            index for index, node in enumerate(order) if node.closest("header") is not None
        ]
        main_at = [index for index, node in enumerate(order) if node.closest("main") is not None]
        if header_at and main_at and max(header_at) > min(main_at):
            problems.append("focus-order: a header control follows a main-content control (2.4.3)")

    for form in page.find_all("form"):
        seen: set[str] = set()
        for control in form.find_all("input", "select", "textarea"):
            name = control.attrs.get("name", "")
            kind = control.attrs.get("type", "text").lower()
            if not name or kind in _UNLABELLED_INPUT_TYPES:
                continue
            key = f"{name}"
            if key in seen:
                problems.append(f"redundant-entry: <form> asks for {name!r} twice (3.3.7)")
            seen.add(key)

    for node in page.walk():
        for handler in ("onpaste", "oncopy", "oncut"):
            if handler in node.attrs:
                problems.append(f"accessible-auth: <{node.tag} {handler}> blocks a paste (3.3.8)")
        if node.tag == "input" and node.attrs.get("type") == "password":
            autocomplete = node.attrs.get("autocomplete", "").lower()
            if autocomplete in {"off", "new-password"}:
                problems.append(
                    f"accessible-auth: the credential field sets autocomplete={autocomplete!r}, "
                    "which tells a password manager not to offer to fill it (3.3.8)"
                )
    return problems


# --------------------------------------------------------------------------- the style rules
def _declarations(css: str) -> list[tuple[str, str, str]]:
    """``(selector, property, value)`` for every declaration in a stylesheet."""
    found: list[tuple[str, str, str]] = []
    for block in re.finditer(r"([^{}]+)\{([^{}]*)\}", _CSS_COMMENT.sub(" ", css)):
        selector = " ".join(block.group(1).split())
        for name, value in _DECLARATION.findall(block.group(2)):
            found.append((selector, name.lower(), value.strip()))
    return found


def _style_rules(fields: dict[str, str]) -> list[str]:
    """The rules that live in the stylesheet and the token file rather than in a page."""
    problems: list[str] = []
    css = (Path(fields["templates"]) / "static" / "app.css").read_text(encoding="utf-8")
    declarations = _declarations(css)

    # 2.4.7 focus visible: a ring from a token, and every suppression has a counterpart.
    rings = [item for item in declarations if "focus-visible" in item[0] and item[1] == "outline"]
    if not rings:
        problems.append("focus-visible: no :focus-visible rule draws an outline (2.4.7)")
    elif all("none" in value or value.strip() in {"0", "0px"} for _, _, value in rings):
        problems.append("focus-visible: :focus-visible sets outline: none (2.4.7)")
    elif not any(
        "var(--focus-ring" in value or "var(--color-focus" in value for _, _, value in rings
    ):
        problems.append("focus-visible: the focus ring is not drawn from a token (2.4.7)")
    suppressions = [item for item in declarations if item[1] == "outline" and "none" in item[2]]
    selectors = {item[0] for item in declarations}
    for selector, _, _ in suppressions:
        # The replacement is the same selector with its `:focus` swapped for `:focus-visible`
        # (a ring on focus would fire on a mouse click too, which is not what 2.4.7 asks for).
        replacement = re.sub(r":focus$", ":focus-visible", selector)
        if replacement not in selectors:
            problems.append(f"focus-visible: {selector!r} removes the outline with no replacement")

    # 2.5.8 target size: the minimum is a token, and it is at least 24 CSS pixels.
    minimum = fields["target-min"]
    if not minimum.endswith(("px", "rem")):
        problems.append("target-size: --target-min is not a length (2.5.8)")
    else:
        as_px = (
            float(minimum.removesuffix("rem")) * 16
            if minimum.endswith("rem")
            else float(minimum.removesuffix("px"))
        )
        if as_px < _TARGET_MIN_PX:
            problems.append(f"target-size: --target-min is {minimum}, below 24 CSS pixels (2.5.8)")
    for wanted in ("button", 'input[type="submit"]'):
        heights = [
            value
            for selector, prop, value in declarations
            if prop == "min-height"
            and "var(--" in value
            and wanted in [part.strip() for part in selector.split(",")]
        ]
        if not heights:
            problems.append(f"target-size: {wanted!r} has no min-height from a token (2.5.8)")

    # 1.4.10 reflow: the page must not require sideways scrolling at 320 CSS pixels.
    if not re.search(r"@media\s*\(max-width:\s*48em\)", css):
        problems.append("reflow: no narrow-width breakpoint for the 768-pixel layout (1.4.10)")
    elif "overflow-x: auto" not in css.split("@media (max-width: 48em)")[-1]:
        problems.append("reflow: a table is not given contained overflow at narrow widths (1.4.10)")
    if "minmax(min(var(--layout-grid-min), 100%), 1fr)" not in css:
        problems.append("reflow: a grid track cannot shrink below --layout-grid-min (1.4.10)")

    # 1.4.12 text spacing: a reader's spacing override must be able to win.
    for selector, prop, value in declarations:
        if "!important" in value and prop in {"line-height", "letter-spacing", "word-spacing"}:
            problems.append(f"text-spacing: {selector!r} marks {prop} !important (1.4.12)")
    return problems


# --------------------------------------------------------------------------- rendering
def _render(directory: Path | None = None) -> Iterator[tuple[str, str, str, dict[str, str]]]:
    """``(screen id, state label, markup, stylesheet fields)`` for every cell of the §5 matrix."""
    from arachne.api import screens
    from arachne.api.app import _build_templates
    from arachne.api.auth import Principal, Role
    from arachne.api.tokens import load_tokens
    from arachne.core.config import Settings

    base = directory or Path(str(files("arachne.templates").joinpath("web")))
    environment = _build_templates(Settings(log_level="CRITICAL"))
    if directory is not None:
        import jinja2

        environment = jinja2.Environment(
            loader=jinja2.FileSystemLoader(str(base)),
            autoescape=jinja2.select_autoescape(["html", "xml"]),
            trim_blocks=True,
            lstrip_blocks=True,
            undefined=jinja2.StrictUndefined,
        )
        environment.globals.update(
            t=lambda key, **params: key,
            tp=lambda key, count, **params: key,
            current_locale=lambda: "en",
        )
        environment.filters.update(
            number=lambda value, decimals=0: str(value), datetime=lambda value: str(value)
        )
    fields: dict[str, str] = {
        "target-min": str(load_tokens()["base"]["--target-min"]),
        "templates": str(base),
    }
    # A signed-in scanner, so the audit sees the chrome (the header nav and its help link)
    # rather than the bare main region a signed-out render would show.
    principal = Principal(label="auditor", role=Role.SCANNER)
    for screen in screens.SCREENS:
        for state in ("ready", *screen.applicable):
            context: dict[str, Any] = dict(screen.context())
            context.update(
                state="loading"
                if state == "loading"
                else ("error" if state == "error" else "ready"),
                empty=state == "empty",
                partial=state == "partial",
                refused=state == "refused",
                theme=None,
                density=None,
                current_path="/ui/",
                principal=principal,
            )
            markup = environment.get_template(screen.template).render(**context)
            yield screen.id, state, markup, fields


def _header_nav(page: Element) -> list[str]:
    """The hrefs of the header's navigation, which is where this interface's help lives."""
    header = next((node for node in page.walk() if node.tag == "header"), None)
    if header is None:
        return []
    nav = next((node for node in header.walk() if node.tag == "nav"), None)
    return [link.attrs.get("href", "") for link in (nav.find_all("a") if nav else [])]


def _help_links(page: Element) -> list[str]:
    """Every link to the documentation the shell offers (WCAG 3.2.6's help affordance)."""
    return [link.attrs.get("href", "") for link in page.find_all("a")]


def _consistent_help(navs: dict[str, list[str]], offered: dict[str, bool]) -> list[str]:
    """3.2.6 — the same help, in the same place, on every screen."""
    problems: list[str] = []
    distinct = {tuple(hrefs) for hrefs in navs.values()}
    if len(distinct) > 1:
        offenders = sorted(
            identifier for identifier, hrefs in navs.items() if tuple(hrefs) != sorted(distinct)[0]
        )
        problems.append(
            f"consistent-help: the main navigation differs between screens: {offenders[:4]}"
        )
    for identifier, present in offered.items():
        if not present:
            problems.append(f"consistent-help: {identifier} offers no link to the help (3.2.6)")
    return problems


def audit(directory: Path | None = None) -> list[Violation]:
    """Every violation on every screen and state (empty means clean)."""
    violations: list[Violation] = []
    style: set[str] | None = None
    navs: dict[str, list[str]] = {}
    help_links: dict[str, bool] = {}
    for identifier, state, markup, fields in _render(directory):
        page, unbalanced = parse(markup)
        problems = _document_rules(page) + _structural_rules(page) + _name_rules(page)
        problems += _interaction_rules(page)
        problems += [f"html-structure: </{tag}> closes nothing" for tag in unbalanced]
        if style is None:
            # The stylesheet is the same for every render, so it is read once.
            style = set(_style_rules(fields))
        if state == "ready":
            # The loaded render is the one a reader navigates: the chrome is compared across
            # screens there, and only there (a state that replaces the content region still
            # renders the same header, which is the point of comparing it).
            navs[identifier] = _header_nav(page)
            help_links[identifier] = any(href.startswith("/docs") for href in _help_links(page))
        for problem in problems:
            rule, _, detail = problem.partition(": ")
            violations.append(Violation(identifier, state, rule, detail))
    for problem in sorted(style or ()):
        rule, _, detail = problem.partition(": ")
        violations.append(Violation("all screens", "stylesheet", rule, detail))
    for problem in _consistent_help(navs, help_links):
        rule, _, detail = problem.partition(": ")
        violations.append(Violation("all screens", "ready", rule, detail))
    return violations


# --------------------------------------------------------------------------- self-test
#: Markup that breaks every DOM rule at once, so ``--self-test`` can prove each one fires.
_OFFENDING: Final = """\
<html>
<head><title></title>
<meta name="viewport" content="width=1024, user-scalable=no"></head>
<body>
<header><a href="/ui/">Home</a></header>
<nav><a href="/x"></a></nav>
<nav></nav>
<main>
<h1 id="dup">One</h1><h4>Skipped</h4>
<p id="dup">Two</p>
<img src="x.png">
<button aria-labelledby="missing"></button>
<span aria-hidden="true"><button>Hidden</button></span>
<div aria-bogus="1"></div>
<button tabindex="3">Later</button>
<a href="/y"><button>Nested</button></a>
<form>
  <input name="token" type="password" autocomplete="off" onpaste="return false">
  <input name="token">
</form>
  <dialog>Sheet</dialog>
</main>
<header><button>After the main content</button></header>
</body>
</section>
</html>
"""

_SELF_TEST_CSS: Final = """
button { min-height: var(--space-1); }
a:focus { outline: none; }
"""


def self_test() -> list[str]:
    """The rules that did *not* fire on the planted markup (empty means the audit works)."""
    page, unbalanced = parse(_OFFENDING)
    problems = _document_rules(page) + _structural_rules(page) + _name_rules(page)
    problems += _interaction_rules(page)
    problems += [f"html-structure: </{tag}> closes nothing" for tag in unbalanced]
    fired = {problem.split(":", 1)[0] for problem in problems}
    expected = {
        "accessible-auth",
        "accessible-name",
        "aria-hidden-focus",
        "aria-reference-valid",
        "aria-valid-attr",
        "document-lang",
        "document-title",
        "duplicate-id",
        "focus-order",
        "heading-order",
        "html-structure",
        "landmark-one-main",
        "modal-labelled",
        "nested-interactive",
        "redundant-entry",
        "tabindex-positive",
        "viewport",
    }
    return sorted(expected - fired)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m arachne.api.a11y")
    parser.add_argument("--self-test", action="store_true", help="prove every DOM rule fires")
    parser.add_argument("--tab-order", action="store_true", help="print the keyboard order")
    args = parser.parse_args(argv)

    if args.self_test:
        silent = self_test()
        if silent:
            print(f"FAIL the audit is blind to: {', '.join(silent)}")  # noqa: T201
            return 1
        print("self-test: every DOM rule fired on the planted markup")  # noqa: T201
        return 0

    if args.tab_order:
        for identifier, state, markup, _ in _render():
            page, _ = parse(markup)
            names = tab_order(page)
            print(f"{identifier}[{state}] {len(names)} stop(s)")  # noqa: T201
            print("  " + " -> ".join(names[:12]) + (" -> …" if len(names) > 12 else ""))  # noqa: T201
        return 0

    violations = audit()
    for item in violations:
        print(f"FAIL {item}")  # noqa: T201
    renders = sum(1 for _ in _render())
    print(f"{renders} screen/state render(s) audited, {len(violations)} violation(s)")  # noqa: T201
    return 1 if violations else 0


if __name__ == "__main__":  # pragma: no cover - exercised through main()
    raise SystemExit(main())

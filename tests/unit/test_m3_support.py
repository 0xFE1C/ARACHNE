"""The M3 support layer: the corpus, the URL/body arithmetic and the oracle classifiers.

These are the pure parts of M3 — payload data, parameter substitution, body comparison, the
reflection classifier, the catch-all/not-found logic and the multipart encoder. They are worth
testing in isolation because every oracle's precision is decided here: a wrong marker turns
every reflected page into an XSS finding, and a wrong catch-all test turns an SPA into a
wordlist of fake endpoints.
"""

from __future__ import annotations

import pytest

from arachne.core.errors import ConfigurationError
from arachne.modules.m3.inventory import (
    Page,
    extract_document,
    normalize_body,
    origin_of,
    same_origin,
    url_param_names,
    with_params,
)
from arachne.modules.m3.payloads import load_payloads, load_wordlist, parse_payloads
from arachne.modules.m3.support import (
    BodyDelta,
    classify_reflection,
    cookie_flag_summary,
    is_catchall,
    is_probably_not_found,
    multipart_body,
    nonce,
    text_ratio,
)


def page(url: str, body: str, *, status: int = 200) -> Page:
    return Page(
        url=url, status=status, headers={}, body=body, content_type="text/html", elapsed_ms=1.0
    )


# ------------------------------------------------------------------ the corpus
def test_the_shipped_corpus_loads_and_is_complete() -> None:
    payloads = load_payloads()
    assert payloads.version
    assert payloads.boolean_probes()
    assert len(payloads.upload_extensions()) >= 3
    assert payloads.traversal_markers()
    assert payloads.header_baseline(https=True)
    assert "next" in payloads.strings("params", "redirect")
    assert "id" in payloads.strings("params", "object_ids")


def test_the_shipped_error_signatures_cover_the_named_families() -> None:
    signatures = load_payloads().sqli_error_signatures()
    assert {"mysql", "postgresql", "mssql", "oracle", "sqlite"} <= set(signatures)
    combined = load_payloads().sql_error_regex()
    assert combined.search("You have an error in your SQL syntax; check the manual")
    assert combined.search("PostgreSQL ERROR: unterminated quoted string")
    assert combined.search("sqlite3.OperationalError: unrecognized token")
    assert combined.search("Unclosed quotation mark after the character string") is not None


def test_a_broken_corpus_fails_at_load_time() -> None:
    with pytest.raises(ConfigurationError, match="section 'sqli'"):
        parse_payloads({"version": "1"})


def test_the_hidden_path_wordlist_loads() -> None:
    entries = load_wordlist("wordlists/hidden-paths.txt")
    assert "/admin/" in entries and "/swagger.json" in entries
    assert len(entries) > 20


# ------------------------------------------------------------------ url arithmetic
@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://h.example/p", ()),
        ("https://h.example/p?a=1", ("a",)),
        ("https://h.example/p?a=1&b=2&a=3", ("a", "b")),
        ("https://h.example/p?flag", ("flag",)),
    ],
)
def test_query_parameter_names(url: str, expected: tuple[str, ...]) -> None:
    assert url_param_names(url) == expected


def test_with_params_replaces_and_appends_without_disturbing_the_rest() -> None:
    replaced = with_params("https://h/p?a=1&b=2", {"a": "x'y"})
    assert replaced == "https://h/p?a=x%27y&b=2"
    appended = with_params("https://h/p?a=1", {"new": "<v>"})
    assert appended == "https://h/p?a=1&new=%3Cv%3E"


def test_origin_is_scheme_host_port() -> None:
    assert origin_of("https://H.Example:443/x") == "https://h.example:443"
    assert origin_of("http://h.example/x") == "http://h.example:80"
    assert same_origin("http://h.example/x", origin_of("http://h.example/"))
    assert not same_origin("https://h.example/x", origin_of("http://h.example/"))


# ------------------------------------------------------------------ body comparison
def test_normalize_body_collapses_whitespace() -> None:
    assert normalize_body("  a \n\t b  ") == "a b"


def test_text_ratio_is_one_for_equal_bodies_and_low_for_unrelated_ones() -> None:
    assert text_ratio("<p>a</p>", "<p>a</p>") == 1.0
    assert text_ratio("", "") == 1.0
    assert text_ratio("x" * 100, "y" * 100) < 0.2


def test_body_delta_significance_needs_a_real_difference() -> None:
    same = BodyDelta(
        baseline_status=200, probe_status=200, baseline_length=10, probe_length=10, ratio=1.0
    )
    assert not same.significant()
    changed = BodyDelta(
        baseline_status=200, probe_status=500, baseline_length=10, probe_length=90, ratio=0.1
    )
    assert changed.significant()
    assert changed.status_changed and changed.length_delta == 80
    assert changed.to_dict()["status_changed"] is True


# ------------------------------------------------------------------ reflection classifier
def test_an_unencoded_marker_in_html_is_html_context() -> None:
    marker = nonce()
    body = f"<p>you searched for <a{marker}>\"'{marker}</p>"
    reflection = classify_reflection(body, nonce=marker)
    assert reflection is not None and reflection.context == "html"


def test_an_escaped_angle_bracket_but_raw_quote_is_attribute_context() -> None:
    marker = nonce()
    body = f"<input value='&lt;a{marker}&gt;&quot;'{marker}'>"
    reflection = classify_reflection(body, nonce=marker)
    assert reflection is not None and reflection.context == "attribute"


def test_a_bare_marker_inside_a_script_block_is_script_context() -> None:
    marker = nonce()
    body = f"<script>var q = '&lt;{marker}&gt;';</script>"
    reflection = classify_reflection(body, nonce=marker)
    assert reflection is not None and reflection.context == "script"


def test_a_fully_encoded_reflection_is_not_a_finding() -> None:
    marker = nonce()
    body = f"<p>&lt;a{marker}&gt;&quot;&#39;{marker}</p>"
    assert classify_reflection(body, nonce=marker) is None


def test_a_marker_that_is_absent_is_not_a_reflection() -> None:
    assert classify_reflection("<p>nothing here</p>", nonce=nonce()) is None


# ------------------------------------------------------------------ not-found / catch-all
def test_a_page_matching_the_not_found_page_is_not_a_discovery() -> None:
    not_found = page("http://h/missing", "<h1>404 Not Found</h1>", status=404)
    matching = page("http://h/x", "<h1>404 Not Found</h1>", status=404)
    assert is_probably_not_found(matching, not_found)
    assert not is_probably_not_found(page("http://h/x", "<h1>Real page</h1>"), not_found)


def test_an_spa_shell_is_a_catch_all_even_though_it_is_not_the_404_page() -> None:
    shell = "<html><body><div id='app'></div><script src='/app.js'></script></body></html>"
    root = page("http://h/", shell)
    not_found = page("http://h/missing", "<h1>404</h1>", status=404)
    assert is_catchall(page("http://h/api/v1", shell), not_found=not_found, root=root)
    admin = page("http://h/admin", "<h1>Admin console</h1>")
    assert not is_catchall(admin, not_found=not_found, root=root)


# ------------------------------------------------------------------ cookies / multipart
def test_cookie_flag_summary_reports_the_missing_attributes() -> None:
    from arachne.core.http import parse_set_cookie

    weak = parse_set_cookie("PHPSESSID=abc; path=/")
    assert weak is not None
    summary = cookie_flag_summary([weak])
    assert summary["insecure_flags"] is True
    assert summary["missing"] == ["httponly", "samesite", "secure"]
    assert summary["names"] == ["PHPSESSID"]
    # The value never appears anywhere in the projection.
    assert "abc" not in repr(summary)


def test_multipart_body_encodes_fields_and_a_file_part() -> None:
    body, content_type = multipart_body(
        {"note": "hello"}, [("file", "a.php", "application/x-php", b"MARKER")]
    )
    assert content_type.startswith("multipart/form-data; boundary=")
    assert b'name="note"' in body and b"hello" in body
    assert b'filename="a.php"' in body and b"application/x-php" in body and b"MARKER" in body
    assert body.rstrip().endswith(b"--")


# ------------------------------------------------------------------ document extraction
def test_extract_document_finds_links_and_forms() -> None:
    html = (
        "<a href='/a'>a</a><a href='#frag'>frag</a>"
        "<script src='/app.js'></script>"
        "<form action='/login' method='post'>"
        "<input type='text' name='username'><input type='password' name='password'>"
        "<input type='file' name='avatar'><select name='role'></select></form>"
    )
    links, forms = extract_document(html, "http://h/")
    assert "http://h/a" in links and "http://h/app.js" in links
    assert all("frag" not in link for link in links)
    assert len(forms) == 1
    form = forms[0]
    assert form.action == "http://h/login" and form.is_post
    assert form.input_names() == ("username", "password", "avatar", "role")
    assert form.password_inputs()[0].name == "password"
    assert form.file_inputs()[0].name == "avatar"
    assert form.any_input_named(["user", "username"]) == "username"

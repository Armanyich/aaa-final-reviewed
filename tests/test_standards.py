"""Tests for standards metadata helpers."""

from __future__ import annotations

import pytest

from webconf_audit.standards import owasp_top10_2021


def test_owasp_top10_2021_rejects_unknown_category() -> None:
    with pytest.raises(ValueError, match="Unsupported OWASP Top 10 2021 category"):
        owasp_top10_2021("A99:2021")


def test_owasp_top10_2021_accepts_all_categories() -> None:
    categories = [
        "A01:2021",
        "A02:2021",
        "A03:2021",
        "A04:2021",
        "A05:2021",
        "A06:2021",
        "A07:2021",
        "A08:2021",
        "A09:2021",
        "A10:2021",
    ]

    refs = [owasp_top10_2021(category) for category in categories]

    assert [ref.reference for ref in refs] == categories
    assert all(ref.url for ref in refs)


def test_owasp_top10_2021_uses_known_category_url() -> None:
    ref = owasp_top10_2021("A10:2021")

    assert ref.standard == "OWASP Top 10"
    assert ref.reference == "A10:2021"
    assert ref.url == "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/"

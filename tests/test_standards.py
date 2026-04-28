"""Tests for standards metadata helpers."""

from __future__ import annotations

import pytest

from webconf_audit.standards import owasp_top10_2021


def test_owasp_top10_2021_rejects_unknown_category() -> None:
    with pytest.raises(ValueError, match="Unsupported OWASP Top 10 2021 category"):
        owasp_top10_2021("A99:2021")


def test_owasp_top10_2021_uses_known_category_url() -> None:
    ref = owasp_top10_2021("A02:2021")

    assert ref.standard == "OWASP Top 10"
    assert ref.reference == "A02:2021"
    assert ref.url == "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"

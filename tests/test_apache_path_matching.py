from __future__ import annotations

from pathlib import Path

from webconf_audit.local.apache.path_matching import (
    directory_path_covers,
    normalize_path_for_match,
    path_match_specificity,
)


def test_directory_path_covers_exact_and_child_paths() -> None:
    assert directory_path_covers(Path("/var/www"), Path("/var/www"))
    assert directory_path_covers(Path("/var/www/site"), Path("/var/www"))


def test_directory_path_does_not_match_sibling_prefix() -> None:
    assert not directory_path_covers(Path("/var/www2/site"), Path("/var/www"))


def test_default_matching_preserves_case_for_posix_style_paths() -> None:
    assert not directory_path_covers(Path("/Var/WWW"), Path("/var/www"))


def test_case_insensitive_matching_can_be_requested() -> None:
    assert directory_path_covers(
        Path("/Var/WWW/Site"),
        Path("/var/www"),
        case_sensitive=False,
    )


def test_path_specificity_uses_normalized_match_key() -> None:
    path = Path("/var/www/")

    assert path_match_specificity(path) == len(normalize_path_for_match(path))

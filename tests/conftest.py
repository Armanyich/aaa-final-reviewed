from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _disable_ambient_iis_live_registry(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep IIS tests independent from the developer/CI Windows registry."""
    from webconf_audit.local.iis import registry as iis_registry

    monkeypatch.setattr(iis_registry, "read_live_registry", lambda: (None, []))

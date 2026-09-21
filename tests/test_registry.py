"""Tests for the module registry and dependency-ordered resolution."""

from __future__ import annotations

import pytest

from vxrecon.core.errors import ConfigError
from vxrecon.core.registry import ModuleSpec, Registry


class _Dummy:
    def __init__(self, *a, **k) -> None:
        pass


def _spec(
    name: str,
    kind: str = "analyzer",
    consumes: tuple[str, ...] = (),
    depends: tuple[str, ...] = (),
) -> ModuleSpec:
    return ModuleSpec(name=name, kind=kind, factory=_Dummy, consumes=consumes, depends=depends)


def test_register_and_get() -> None:
    reg = Registry()
    reg.register(_spec("dns"))
    assert reg.has("analyzer", "dns")
    assert reg.get("analyzer", "dns").name == "dns"


def test_duplicate_registration_rejected() -> None:
    reg = Registry()
    reg.register(_spec("dns"))
    with pytest.raises(ConfigError):
        reg.register(_spec("dns"))


def test_invalid_kind_rejected() -> None:
    reg = Registry()
    with pytest.raises(ConfigError):
        reg.register(ModuleSpec(name="x", kind="bogus", factory=_Dummy))


def test_dependency_ordering() -> None:
    reg = Registry()
    reg.register(_spec("http"))
    reg.register(_spec("tech", depends=("http",)))
    order = [s.name for s in reg.resolve_order("analyzer", ["tech", "http"])]
    assert order.index("http") < order.index("tech")


def test_circular_dependency_detected() -> None:
    reg = Registry()
    reg.register(_spec("a", depends=("b",)))
    reg.register(_spec("b", depends=("a",)))
    with pytest.raises(ConfigError):
        reg.resolve_order("analyzer", ["a", "b"])


def test_missing_dependency_is_ignored() -> None:
    reg = Registry()
    reg.register(_spec("tech", depends=("http",)))
    order = [s.name for s in reg.resolve_order("analyzer", ["tech"])]
    assert order == ["tech"]


def test_collector_names_do_not_collide_with_analyzer_names() -> None:
    # Same name, different kind: analyzer "dns" consumes collector "dns" but
    # must not be treated as depending on *itself*.
    reg = Registry()
    reg.register(_spec("dns", kind="collector"))
    reg.register(_spec("dns", kind="analyzer", consumes=("dns",)))
    order = [s.name for s in reg.resolve_order("analyzer", ["dns"])]
    assert order == ["dns"]

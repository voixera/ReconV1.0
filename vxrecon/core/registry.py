"""Module registry.

Collectors, analyzers and correlators register themselves by name. The
pipeline resolves dependency order from each module's ``consumes`` /
``provides`` metadata. Registration is explicit (no magic import scanning) to
keep the tool auditable.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Type

from vxrecon.core.errors import ConfigError


@dataclass
class ModuleSpec:
    """Descriptor for a registered module.

    Parameters
    ----------
    name:
        Unique module identifier, e.g. ``"dns"``.
    kind:
        One of ``"collector"``, ``"analyzer"``, ``"correlator"``.
    factory:
        Callable returning an instance (usually the class itself).
    consumes:
        Names of *collectors* whose output this module reads. This is
        documentation for analyzers; it does NOT drive ordering because
        collector and analyzer namespaces are separate.
    depends:
        Names of other modules *of the same kind* that must run first. This
        drives dependency ordering.
    provides:
        Logical data keys this module emits (used for diagnostics).
    requires_network:
        Whether the module performs network I/O. Used by ``--offline``.
    """

    name: str
    kind: str
    factory: Callable[..., object]
    consumes: tuple[str, ...] = ()
    depends: tuple[str, ...] = ()
    provides: tuple[str, ...] = ()
    requires_network: bool = False
    description: str = ""
    tags: tuple[str, ...] = field(default_factory=tuple)


class Registry:
    """In-memory registry of module specs keyed by ``(kind, name)``."""

    def __init__(self) -> None:
        self._modules: dict[str, ModuleSpec] = {}

    def register(self, spec: ModuleSpec) -> None:
        if spec.kind not in {"collector", "analyzer", "correlator"}:
            raise ConfigError(f"Unknown module kind: {spec.kind!r}")
        key = f"{spec.kind}:{spec.name}"
        if key in self._modules:
            raise ConfigError(f"Duplicate module registration: {key}")
        self._modules[key] = spec

    def get(self, kind: str, name: str) -> ModuleSpec:
        key = f"{kind}:{name}"
        if key not in self._modules:
            raise ConfigError(f"Module not registered: {key}")
        return self._modules[key]

    def has(self, kind: str, name: str) -> bool:
        return f"{kind}:{name}" in self._modules

    def all(self, kind: str | None = None) -> list[ModuleSpec]:
        specs = self._modules.values()
        if kind is not None:
            specs = [s for s in specs if s.kind == kind]
        return sorted(specs, key=lambda s: (s.kind, s.name))

    def resolve_order(self, kind: str, names: list[str]) -> list[ModuleSpec]:
        """Return the modules in dependency order for the requested names.

        Only ordering *within the requested set* is enforced; a dependency that
        is not part of the request is ignored (the pipeline will still run the
        requested modules even if an optional dependency is absent).
        """

        requested = {n for n in names}
        specs = {n: self.get(kind, n) for n in names}
        ordered: list[ModuleSpec] = []
        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(name: str) -> None:
            if name in visited:
                return
            if name in visiting:
                raise ConfigError(f"Circular module dependency at {name!r}")
            visiting.add(name)
            for dep in specs[name].depends:
                if dep in requested:
                    visit(dep)
            visiting.discard(name)
            visited.add(name)
            ordered.append(specs[name])

        for name in names:
            visit(name)
        return ordered

    def clear(self) -> None:
        self._modules.clear()


# A module-level default registry. Tests may construct isolated registries.
DEFAULT_REGISTRY = Registry()


def register(spec: ModuleSpec, registry: Registry | None = None) -> None:
    """Register ``spec`` into the given (or default) registry."""

    (registry or DEFAULT_REGISTRY).register(spec)


CollectorType = Type[object]

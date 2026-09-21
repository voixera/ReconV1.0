"""Module bootstrap: register all built-in modules into a registry.

Registration is explicit (no import magic) so the tool's capabilities are
auditable at a glance. Called once at CLI startup.
"""

from __future__ import annotations

from vxrecon.core.registry import DEFAULT_REGISTRY, ModuleSpec, Registry


def register_core_modules(registry: Registry | None = None) -> Registry:
    """Register the built-in Phase 2 modules. Idempotent."""

    reg = registry or DEFAULT_REGISTRY
    if reg.has("collector", "dns"):
        return reg  # already registered

    from vxrecon.analyzers.dns_analyzer import DnsAnalyzer
    from vxrecon.analyzers.favicon_analyzer import FaviconAnalyzer
    from vxrecon.analyzers.files_analyzer import PublicFilesAnalyzer
    from vxrecon.analyzers.http_analyzer import HttpAnalyzer
    from vxrecon.analyzers.js_endpoint import JsEndpointAnalyzer
    from vxrecon.analyzers.metadata_analyzer import MetadataAnalyzer
    from vxrecon.analyzers.rdap_analyzer import RdapAnalyzer
    from vxrecon.analyzers.sourcemap import SourceMapAnalyzer
    from vxrecon.analyzers.subdomain_analyzer import SubdomainAnalyzer
    from vxrecon.analyzers.technology import TechnologyAnalyzer
    from vxrecon.analyzers.tls_analyzer import TlsAnalyzer
    from vxrecon.analyzers.website_dna import WebsiteDnaAnalyzer
    from vxrecon.collectors.ct_collector import CtSubdomainCollector
    from vxrecon.collectors.dns_collector import DnsCollector
    from vxrecon.collectors.favicon_collector import FaviconCollector
    from vxrecon.collectors.files_collector import PublicFilesCollector
    from vxrecon.collectors.http_collector import HttpCollector
    from vxrecon.collectors.js_collector import JavaScriptCollector
    from vxrecon.collectors.rdap_collector import RdapCollector
    from vxrecon.collectors.tls_collector import TlsCollector
    from vxrecon.correlators.artifact import ArtifactCorrelator
    from vxrecon.correlators.cert_explorer import CertificateExplorer
    from vxrecon.correlators.infra_mapper import InfraMapper

    # Collectors (network I/O).
    reg.register(
        ModuleSpec(
            name="dns",
            kind="collector",
            factory=DnsCollector,
            requires_network=True,
            provides=("dns",),
            description="DNS record collection",
            tags=("dns",),
        )
    )
    reg.register(
        ModuleSpec(
            name="tls",
            kind="collector",
            factory=TlsCollector,
            requires_network=True,
            provides=("certificate",),
            description="TLS certificate collection",
            tags=("tls", "cert"),
        )
    )
    reg.register(
        ModuleSpec(
            name="rdap",
            kind="collector",
            factory=RdapCollector,
            requires_network=True,
            provides=("registration", "network"),
            description="RDAP registration/network collection",
            tags=("rdap", "whois"),
        )
    )
    reg.register(
        ModuleSpec(
            name="http",
            kind="collector",
            factory=HttpCollector,
            requires_network=True,
            provides=("http",),
            description="HTTP response behaviour collection",
            tags=("http", "web"),
        )
    )
    reg.register(
        ModuleSpec(
            name="ct",
            kind="collector",
            factory=CtSubdomainCollector,
            requires_network=True,
            provides=("subdomains",),
            description="Certificate Transparency subdomain discovery",
            tags=("ct", "subdomains", "passive"),
        )
    )
    reg.register(
        ModuleSpec(
            name="javascript",
            kind="collector",
            factory=JavaScriptCollector,
            requires_network=True,
            provides=("javascript",),
            description="Public JavaScript collection",
            tags=("js", "web"),
        )
    )
    reg.register(
        ModuleSpec(
            name="files",
            kind="collector",
            factory=PublicFilesCollector,
            requires_network=True,
            provides=("robots", "sitemap"),
            description="robots.txt and sitemap collection",
            tags=("files", "robots", "sitemap"),
        )
    )
    reg.register(
        ModuleSpec(
            name="favicon",
            kind="collector",
            factory=FaviconCollector,
            requires_network=True,
            provides=("favicon",),
            description="Favicon collection for fingerprinting",
            tags=("favicon", "image"),
        )
    )

    # Analyzers (pure).
    reg.register(
        ModuleSpec(name="dns", kind="analyzer", factory=DnsAnalyzer, consumes=("dns",))
    )
    reg.register(
        ModuleSpec(name="tls", kind="analyzer", factory=TlsAnalyzer, consumes=("tls",))
    )
    reg.register(
        ModuleSpec(name="rdap", kind="analyzer", factory=RdapAnalyzer, consumes=("rdap",))
    )
    reg.register(
        ModuleSpec(name="http", kind="analyzer", factory=HttpAnalyzer, consumes=("http",))
    )
    reg.register(
        ModuleSpec(
            name="technology",
            kind="analyzer",
            factory=TechnologyAnalyzer,
            consumes=("http",),
        )
    )
    reg.register(
        ModuleSpec(
            name="website_dna",
            kind="analyzer",
            factory=WebsiteDnaAnalyzer,
            consumes=("http", "technology"),
            depends=("technology",),
        )
    )
    reg.register(
        ModuleSpec(
            name="subdomains",
            kind="analyzer",
            factory=SubdomainAnalyzer,
            consumes=("ct",),
        )
    )
    reg.register(
        ModuleSpec(
            name="js_endpoints",
            kind="analyzer",
            factory=JsEndpointAnalyzer,
            consumes=("javascript",),
        )
    )
    reg.register(
        ModuleSpec(
            name="sourcemap",
            kind="analyzer",
            factory=SourceMapAnalyzer,
            consumes=("javascript",),
            depends=("js_endpoints",),
        )
    )
    reg.register(
        ModuleSpec(
            name="files",
            kind="analyzer",
            factory=PublicFilesAnalyzer,
            consumes=("files",),
        )
    )
    reg.register(
        ModuleSpec(
            name="favicon",
            kind="analyzer",
            factory=FaviconAnalyzer,
            consumes=("favicon",),
        )
    )

    # Correlators (pure).
    reg.register(
        ModuleSpec(name="infra_mapper", kind="correlator", factory=InfraMapper)
    )
    reg.register(
        ModuleSpec(name="cert_explorer", kind="correlator", factory=CertificateExplorer)
    )
    reg.register(
        ModuleSpec(name="artifact", kind="correlator", factory=ArtifactCorrelator)
    )
    return reg

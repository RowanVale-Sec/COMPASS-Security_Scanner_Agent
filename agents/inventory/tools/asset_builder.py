"""
Inventory Tool - Asset Inventory Builder
Consolidates SBOM, architecture, and DFD into a unified asset inventory.
"""

import json
from typing import Annotated
from pydantic import Field


def build_asset_inventory(
    sbom_json: Annotated[str, Field(description="JSON string of SBOM data from generate_enhanced_sbom")],
    architecture_json: Annotated[str, Field(description="JSON string of architecture model from analyze_architecture")],
    dfd_json: Annotated[str, Field(description="JSON string of DFD model from analyze_data_flows")]
) -> str:
    """
    Build a consolidated asset inventory from SBOM, architecture, and DFD data.

    Categorizes all discovered assets into:
    - Dependencies (from SBOM)
    - Services (from architecture)
    - Infrastructure (from architecture deployment)
    - Data stores (from DFD)
    - External APIs (from architecture and DFD)

    Returns: JSON string with unified asset inventory.
    """
    print("[Assets] Building consolidated asset inventory")

    try:
        sbom = json.loads(sbom_json)
    except json.JSONDecodeError:
        sbom = {}

    try:
        architecture = json.loads(architecture_json)
    except json.JSONDecodeError:
        architecture = {}

    try:
        dfd = json.loads(dfd_json)
    except json.JSONDecodeError:
        dfd = {}

    assets = []

    # 1. Dependencies from SBOM
    dependency_count = 0
    for pkg in sbom.get('packages', []):
        assets.append({
            "category": "dependency",
            "name": pkg.get('name', 'unknown'),
            "version": pkg.get('version', 'unknown'),
            "technology": _infer_ecosystem(pkg.get('purl', '')),
            "purl": pkg.get('purl', ''),
            "license": pkg.get('license', 'unknown'),
            "risk_level": pkg.get('risk_level', 'NONE'),
            "known_vulnerabilities": len(pkg.get('known_vulnerabilities', []))
        })
        dependency_count += 1

    # 2. Services from architecture
    service_count = 0
    for component in architecture.get('components', []):
        comp_type = component.get('type', 'service')
        if comp_type in ('service', 'gateway'):
            assets.append({
                "category": "service",
                "name": component.get('name', ''),
                "technology": component.get('technology', ''),
                "exposure": component.get('exposure', 'internal'),
                "ports": component.get('ports', []),
                "dependencies": component.get('dependencies', []),
                "description": component.get('description', '')
            })
            service_count += 1

    # 3. Infrastructure from architecture
    infra_count = 0
    deployment = architecture.get('deployment', {})
    if deployment.get('containerized'):
        assets.append({
            "category": "infrastructure",
            "name": "Container Runtime",
            "technology": "Docker",
            "orchestration": deployment.get('orchestration', 'none'),
            "cloud_provider": deployment.get('cloud_provider', 'none')
        })
        infra_count += 1

    for component in architecture.get('components', []):
        if component.get('type') in ('database', 'cache', 'queue', 'storage'):
            assets.append({
                "category": "infrastructure",
                "name": component.get('name', ''),
                "type": component.get('type', ''),
                "technology": component.get('technology', ''),
                "description": component.get('description', '')
            })
            infra_count += 1

    # 4. Data stores from DFD
    data_store_count = 0
    for store in dfd.get('data_stores', []):
        # Avoid duplicating with infrastructure components
        store_name = store.get('name', '')
        if not any(a.get('name') == store_name and a.get('category') == 'infrastructure' for a in assets):
            assets.append({
                "category": "data_store",
                "name": store_name,
                "type": store.get('type', ''),
                "technology": store.get('technology', ''),
                "data_sensitivity": store.get('data_sensitivity', 'internal'),
                "encryption_at_rest": store.get('encryption_at_rest', False),
                "data_types": store.get('data_types_stored', [])
            })
            data_store_count += 1

    # 5. External APIs from architecture
    external_count = 0
    for component in architecture.get('components', []):
        if component.get('type') == 'external_api':
            assets.append({
                "category": "external_api",
                "name": component.get('name', ''),
                "technology": component.get('technology', ''),
                "description": component.get('description', '')
            })
            external_count += 1

    inventory = {
        "total_assets": len(assets),
        "by_category": {
            "dependencies": dependency_count,
            "services": service_count,
            "infrastructure": infra_count,
            "data_stores": data_store_count,
            "external_apis": external_count
        },
        "assets": assets
    }

    print(f"[Assets] Inventory complete: {len(assets)} total assets")
    print(f"  Dependencies: {dependency_count}, Services: {service_count}, "
          f"Infrastructure: {infra_count}, Data Stores: {data_store_count}, "
          f"External APIs: {external_count}")

    return json.dumps(inventory, indent=2)


def _infer_ecosystem(purl: str) -> str:
    """Infer package ecosystem from PURL."""
    if not purl:
        return "unknown"
    if purl.startswith('pkg:pypi/'):
        return "Python (PyPI)"
    elif purl.startswith('pkg:npm/'):
        return "JavaScript (npm)"
    elif purl.startswith('pkg:maven/'):
        return "Java (Maven)"
    elif purl.startswith('pkg:golang/'):
        return "Go"
    elif purl.startswith('pkg:gem/'):
        return "Ruby (RubyGems)"
    elif purl.startswith('pkg:nuget/'):
        return ".NET (NuGet)"
    elif purl.startswith('pkg:cargo/'):
        return "Rust (Cargo)"
    return "unknown"

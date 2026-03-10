"""
COMPASS Syft MCP Server - Enhanced SBOM Generation and Dependency Analysis.

Provides SBOM generation with rich package metadata extraction:
- Package name, version, license
- PURL (Package URL) identifiers
- CPE identifiers
- Supplier/originator information
- Dependency relationships
- File-level package mapping

Endpoints:
- GET /health - Health check
- GET /capabilities - Tool capabilities
- POST /analyze - Generate SBOM from directory
- POST /analyze-image - Generate SBOM from container image
"""

import os
import sys
import json
import uuid
import logging
from typing import Dict, Any, List

sys.path.insert(0, '/app')

from shared.mcp_server_base import MCPServerBase

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SyftMCPServer(MCPServerBase):
    """Enhanced Syft SBOM analysis MCP server with rich metadata extraction."""

    def __init__(self):
        super().__init__("syft")
        # Add image analysis route
        self.app.route('/analyze-image', methods=['POST'])(self.analyze_image)

    def get_tool_capabilities(self) -> List[str]:
        return [
            "sbom_generation",
            "dependency_detection",
            "license_detection",
            "purl_extraction",
            "cpe_extraction",
            "relationship_mapping",
            "container_image_sbom"
        ]

    def get_supported_languages(self) -> List[str]:
        return ["java", "python", "go", "javascript", "ruby", "php", "dotnet", "rust"]

    def get_tool_version(self) -> str:
        result = self.run_command(["/app/syft", "version"])
        if result["success"]:
            return result["stdout"].strip().split("\n")[0]
        return "unknown"

    def execute_analysis(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Execute Syft SBOM analysis on a directory."""
        repo_path = data.get('repo_path', '/workspace')
        output_format = data.get('output_format', 'spdx-json')

        output_file = f"/tmp/sbom_{uuid.uuid4().hex}.{output_format}"
        cmd = [
            "/app/syft",
            "dir:" + repo_path,
            "-o", f"{output_format}={output_file}"
        ]

        result = self.run_command(cmd)

        if not result["success"]:
            raise Exception(f"Syft analysis failed: {result['stderr']}")

        sbom_data = {}
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                sbom_data = json.load(f)

        findings = self._parse_sbom_enhanced(sbom_data)
        relationships = self._extract_relationships(sbom_data)

        return {
            "sbom_file": output_file,
            "findings": findings,
            "relationships": relationships,
            "total_packages": len(findings),
            "execution_time": 0,
            "sbom_format": output_format,
            "sbom_raw": sbom_data
        }

    def analyze_image(self):
        """Generate SBOM from a container image."""
        try:
            from flask import request
            data = request.json
            if not data:
                from flask import jsonify
                return jsonify({"status": "error", "message": "No data provided"}), 400

            image_ref = data.get('image_ref')
            if not image_ref:
                from flask import jsonify
                return jsonify({"status": "error", "message": "image_ref is required"}), 400

            output_file = f"/tmp/sbom_image_{uuid.uuid4().hex}.spdx-json"
            cmd = ["/app/syft", image_ref, "-o", f"spdx-json={output_file}"]

            result = self.run_command(cmd, timeout=600)

            if not result["success"]:
                raise Exception(f"Image SBOM generation failed: {result['stderr']}")

            sbom_data = {}
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    sbom_data = json.load(f)

            findings = self._parse_sbom_enhanced(sbom_data)

            from flask import jsonify
            return jsonify({
                "status": "success",
                "tool": self.tool_name,
                "result": {
                    "findings": findings,
                    "total_packages": len(findings),
                    "image_ref": image_ref,
                    "sbom_format": "spdx-json"
                }
            })

        except Exception as e:
            logger.error(f"Image analysis failed: {str(e)}", exc_info=True)
            from flask import jsonify
            return jsonify({"status": "error", "message": str(e)}), 500

    def _parse_sbom_enhanced(self, sbom_data: Dict) -> List[Dict]:
        """Parse SBOM with rich metadata extraction (CPE, PURL, relationships)."""
        findings = []

        packages = sbom_data.get('packages', [])
        for pkg in packages:
            # Extract PURL and CPE from external references
            purl = ""
            cpe = ""
            for ref in pkg.get('externalRefs', []):
                ref_type = ref.get('referenceType', '')
                ref_locator = ref.get('referenceLocator', '')

                if ref_type == 'purl' or 'purl' in ref_type.lower():
                    purl = ref_locator
                elif ref_type == 'cpe23Type' or 'cpe' in ref_type.lower():
                    cpe = ref_locator

            # Extract supplier info
            supplier = pkg.get('supplier', '')
            if isinstance(supplier, dict):
                supplier = supplier.get('name', '')
            originator = pkg.get('originator', '')
            if isinstance(originator, dict):
                originator = originator.get('name', '')

            # Extract file info
            files_analyzed = pkg.get('filesAnalyzed', False)
            download_location = pkg.get('downloadLocation', '')

            findings.append({
                "type": "dependency",
                "name": pkg.get('name', 'unknown'),
                "version": pkg.get('versionInfo', 'unknown'),
                "license": pkg.get('licenseDeclared', pkg.get('licenseConcluded', 'unknown')),
                "purl": purl,
                "cpe": cpe,
                "supplier": supplier or originator,
                "download_location": download_location,
                "spdx_id": pkg.get('SPDXID', ''),
                "severity": "Info",
                "confidence_score": 1.0,
                "description": f"Package: {pkg.get('name')} {pkg.get('versionInfo', '')}",
                "files_analyzed": files_analyzed
            })

        return findings

    def _extract_relationships(self, sbom_data: Dict) -> List[Dict]:
        """Extract dependency relationships from SBOM."""
        relationships = []
        for rel in sbom_data.get('relationships', []):
            relationships.append({
                "source": rel.get('spdxElementId', ''),
                "target": rel.get('relatedSpdxElement', ''),
                "type": rel.get('relationshipType', '')
            })
        return relationships


if __name__ == '__main__':
    server = SyftMCPServer()
    server.run()

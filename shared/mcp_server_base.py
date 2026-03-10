"""
COMPASS MCP Server Base - Single source of truth for all MCP tool servers.
Replaces the duplicated MCPServerBase in each MCP server file.
"""

import subprocess
import logging
from typing import Dict, Any, List
from abc import ABC, abstractmethod
from flask import Flask, request, jsonify

logger = logging.getLogger(__name__)


class MCPServerBase(ABC):
    """Base class for all MCP tool servers.

    Provides Flask HTTP endpoints:
    - GET /health - Health check
    - GET /capabilities - Tool capabilities
    - POST /analyze - Main analysis endpoint
    """

    def __init__(self, tool_name: str):
        self.app = Flask(__name__)
        self.tool_name = tool_name
        self._setup_routes()

    def _setup_routes(self):
        """Register all HTTP endpoints."""
        self.app.route('/health', methods=['GET'])(self.health_check)
        self.app.route('/capabilities', methods=['GET'])(self.get_capabilities)
        self.app.route('/analyze', methods=['POST'])(self.analyze)

    def health_check(self):
        """Health check endpoint."""
        return jsonify({
            "status": "healthy",
            "tool": self.tool_name,
            "version": self.get_tool_version()
        })

    def get_capabilities(self):
        """Return tool capabilities."""
        return jsonify({
            "tool": self.tool_name,
            "capabilities": self.get_tool_capabilities(),
            "version": self.get_tool_version(),
            "supported_languages": self.get_supported_languages()
        })

    def analyze(self):
        """Main analysis endpoint."""
        try:
            data = request.json
            if not data:
                return jsonify({"status": "error", "message": "No data provided"}), 400

            logger.info(f"Starting analysis with {self.tool_name}")
            result = self.execute_analysis(data)

            return jsonify({
                "status": "success",
                "tool": self.tool_name,
                "result": result
            })
        except Exception as e:
            logger.error(f"Analysis failed: {str(e)}", exc_info=True)
            return jsonify({
                "status": "error",
                "tool": self.tool_name,
                "message": str(e)
            }), 500

    @abstractmethod
    def execute_analysis(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Execute tool-specific analysis. Must be implemented by subclasses."""
        pass

    @abstractmethod
    def get_tool_capabilities(self) -> List[str]:
        """Return list of tool capabilities. Must be implemented by subclasses."""
        pass

    def get_tool_version(self) -> str:
        """Get tool version. Override in subclasses."""
        return "unknown"

    def get_supported_languages(self) -> List[str]:
        """Get supported programming languages. Override in subclasses."""
        return []

    def run_command(self, cmd: List[str], cwd: str = None, timeout: int = 300) -> Dict[str, Any]:
        """Execute a shell command and return results."""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=cwd,
                timeout=timeout
            )
            return {
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode,
                "success": result.returncode == 0
            }
        except subprocess.TimeoutExpired:
            return {
                "stdout": "",
                "stderr": f"Command timed out after {timeout} seconds",
                "returncode": -1,
                "success": False
            }
        except Exception as e:
            return {
                "stdout": "",
                "stderr": str(e),
                "returncode": -1,
                "success": False
            }

    def run(self, host='0.0.0.0', port=8080):
        """Start the Flask server."""
        logger.info(f"Starting {self.tool_name} MCP Server on {host}:{port}")
        self.app.run(host=host, port=port, debug=False)

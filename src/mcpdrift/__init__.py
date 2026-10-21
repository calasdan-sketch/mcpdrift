"""mcpdrift — pin MCP servers' tool surface, fail CI when it drifts."""

from .canon import build_surface, diff_surfaces
from .client import MCPError, fetch_surface

__version__ = "0.1.0"
__all__ = ["build_surface", "diff_surfaces", "fetch_surface", "MCPError", "__version__"]

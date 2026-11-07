"""mcpdrift — pin MCP servers' tool surface, fail CI when it drifts."""

__version__ = "0.3.0"

from .canon import build_surface, diff_raw, diff_surfaces, surface_digests  # noqa: E402
from .client import Capture, MCPError, fetch_capture, fetch_surface, surface_from_file  # noqa: E402
from .risk import Assessed, assess_changes, scan_surface, text_signals  # noqa: E402

__all__ = [
    "build_surface", "diff_raw", "diff_surfaces", "surface_digests",
    "fetch_surface", "fetch_capture", "Capture", "surface_from_file", "MCPError",
    "Assessed", "assess_changes", "scan_surface", "text_signals",
    "__version__",
]

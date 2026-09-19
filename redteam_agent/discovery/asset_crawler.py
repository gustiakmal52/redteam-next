"""Scope-neutral asset reference extraction for the hidden discovery queue.

The crawler does not perform I/O.  ``HiddenAssetEngine`` owns fetching so every
reference still passes ``ScopeManager``, ``TrafficController``, size, depth,
and kill-switch gates.  Keeping this piece separate makes it reusable by the
CLI, Web Local, and a future researcher-owned browser adapter.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from redteam_agent.discovery.js_deep import JSDeepAnalyzer
from redteam_agent.discovery.runtime_config import RuntimeConfigAnalyzer


class AssetCrawler:
    """Produce bounded, provenance-tagged asset candidates without fetching."""

    def __init__(self, *, js_analyzer: Optional[JSDeepAnalyzer] = None,
                 runtime_config: Optional[RuntimeConfigAnalyzer] = None):
        self.js = js_analyzer or JSDeepAnalyzer()
        self.runtime = runtime_config or RuntimeConfigAnalyzer(self.js.redactor)

    def from_html(self, html: str, base_url: str, *, source_file: str = "document") -> List[Dict[str, Any]]:
        return self.js.html_references(html or "", base_url, source_file=source_file)

    def from_script(self, source: str, base_url: str, *, source_file: str = "unknown") -> List[Dict[str, Any]]:
        return self.js.asset_references(source or "", base_url, source_file=source_file)

    def runtime_config_references(self, source: str, base_url: str,
                                  *, source_file: str = "unknown") -> List[Dict[str, Any]]:
        return self.runtime.find_references(source or "", base_url, source_file=source_file)


__all__ = ["AssetCrawler"]

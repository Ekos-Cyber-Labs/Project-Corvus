"""Read-only Wazuh indexer adapter (OpenSearch REST API -> OCSF)."""

from corvus.adapters.wazuh.adapter import (
    ADAPTER_NAME,
    ALERTS_INDEX,
    ARCHIVES_INDEX,
    DEFAULT_OVERLAP_SECONDS,
    STREAM_NAME,
    WazuhAdapter,
)
from corvus.adapters.wazuh.client import IndexerError, ReadOnlyIndexerClient

__all__ = [
    "ADAPTER_NAME",
    "ALERTS_INDEX",
    "ARCHIVES_INDEX",
    "DEFAULT_OVERLAP_SECONDS",
    "STREAM_NAME",
    "IndexerError",
    "ReadOnlyIndexerClient",
    "WazuhAdapter",
]

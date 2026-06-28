from __future__ import annotations

from functools import lru_cache
from typing import Any

from botocore.loaders import Loader


@lru_cache(maxsize=1)
def _region_descriptions() -> dict[str, str]:
    endpoints: dict[str, Any] = Loader().load_data("endpoints")
    descriptions: dict[str, str] = {}
    for partition in endpoints.get("partitions", []):
        for region, data in partition.get("regions", {}).items():
            description = data.get("description")
            if isinstance(description, str):
                descriptions[region] = description
    return descriptions


def region_label(region: str) -> str:
    description = _region_descriptions().get(region)
    return f"{region} ({description})" if description else region


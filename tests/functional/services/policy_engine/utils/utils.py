from dataclasses import dataclass
from typing import List, Optional


@dataclass
class VulnerabilityQueryMetadata:
    severity: Optional[str] = None
    namespace: Optional[str] = None
    affected_package: Optional[str] = None
    vendor_only: bool = True


@dataclass
class VulnerabilityQuery:
    vulnerability_id: str
    query_metadata: Optional[VulnerabilityQueryMetadata]
    affected_images: List[str]

"""Attempts DNS zone transfers (AXFR) against all NS servers of a domain."""

import dns.resolver
import dns.query
import dns.zone
import dns.exception
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class ZoneRecord:
    name: str
    rtype: str
    value: str


@dataclass
class ZoneTransferResult:
    nameserver: str
    success: bool
    records: List[ZoneRecord] = field(default_factory=list)
    error: Optional[str] = None


def get_nameservers(domain: str) -> List[str]:
    try:
        answers = dns.resolver.resolve(domain, "NS", lifetime=5)
        ns_list = []
        for rdata in answers:
            ns = str(rdata.target).rstrip(".")
            # Resolve NS hostname to IP
            try:
                a = dns.resolver.resolve(ns, "A", lifetime=5)
                ns_list.append(str(a[0]))
            except Exception:
                ns_list.append(ns)
        return ns_list
    except Exception:
        return []


def attempt_axfr(domain: str, nameserver: str) -> ZoneTransferResult:
    result = ZoneTransferResult(nameserver=nameserver, success=False)
    try:
        zone = dns.zone.from_xfr(
            dns.query.xfr(nameserver, domain, lifetime=10)
        )
        result.success = True
        for name, node in zone.nodes.items():
            for rdataset in node.rdatasets:
                rtype = dns.rdatatype.to_text(rdataset.rdtype)
                for rdata in rdataset:
                    result.records.append(ZoneRecord(
                        name=str(name),
                        rtype=rtype,
                        value=rdata.to_text(),
                    ))
        result.records.sort(key=lambda r: (r.name, r.rtype))
    except dns.exception.FormError:
        result.error = "AXFR refused or not supported"
    except EOFError:
        result.error = "Connection closed (transfer refused)"
    except Exception as e:
        result.error = str(e)
    return result


def run_zone_transfers(domain: str,
                       nameservers: Optional[List[str]] = None
                       ) -> List[ZoneTransferResult]:
    if nameservers is None:
        nameservers = get_nameservers(domain)

    if not nameservers:
        return [ZoneTransferResult(
            nameserver="(none)",
            success=False,
            error="Could not resolve any NS records",
        )]

    return [attempt_axfr(domain, ns) for ns in nameservers]

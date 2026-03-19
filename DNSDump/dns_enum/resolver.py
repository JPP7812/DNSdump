"""DNS record resolver — queries all common record types for a domain."""

import dns.resolver
import dns.reversename
import dns.exception
from dataclasses import dataclass, field
from typing import List, Optional

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA", "SRV"]


@dataclass
class DnsRecord:
    rtype: str
    value: str
    ttl: int = 0
    priority: Optional[int] = None   # MX / SRV


@dataclass
class DomainResult:
    domain: str
    records: List[DnsRecord] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


def query_record(domain: str, rtype: str,
                 nameserver: Optional[str] = None) -> List[DnsRecord]:
    resolver = dns.resolver.Resolver()
    if nameserver:
        resolver.nameservers = [nameserver]

    results: List[DnsRecord] = []
    try:
        answers = resolver.resolve(domain, rtype, lifetime=5)
        for rdata in answers:
            value = rdata.to_text()
            priority = None

            if rtype == "MX":
                priority = int(rdata.preference)
                value = str(rdata.exchange).rstrip(".")
            elif rtype == "NS":
                value = str(rdata.target).rstrip(".")
            elif rtype == "CNAME":
                value = str(rdata.target).rstrip(".")
            elif rtype == "SOA":
                value = (
                    f"mname={str(rdata.mname).rstrip('.')} "
                    f"rname={str(rdata.rname).rstrip('.')} "
                    f"serial={rdata.serial} "
                    f"refresh={rdata.refresh} "
                    f"retry={rdata.retry} "
                    f"expire={rdata.expire}"
                )
            elif rtype == "TXT":
                value = " ".join(
                    part.decode("utf-8", errors="replace")
                    for part in rdata.strings
                )

            results.append(DnsRecord(
                rtype=rtype,
                value=value,
                ttl=answers.ttl,
                priority=priority,
            ))

    except dns.resolver.NXDOMAIN:
        pass
    except dns.resolver.NoAnswer:
        pass
    except dns.resolver.NoNameservers:
        pass
    except dns.exception.Timeout:
        pass
    except Exception:
        pass

    return results


def resolve_all(domain: str, nameserver: Optional[str] = None) -> DomainResult:
    result = DomainResult(domain=domain)
    for rtype in RECORD_TYPES:
        records = query_record(domain, rtype, nameserver)
        result.records.extend(records)
    return result


def reverse_lookup(ip: str) -> Optional[str]:
    try:
        rev = dns.reversename.from_address(ip)
        answers = dns.resolver.resolve(rev, "PTR", lifetime=5)
        return str(answers[0].target).rstrip(".")
    except Exception:
        return None

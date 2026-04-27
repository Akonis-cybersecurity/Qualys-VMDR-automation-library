import xml.etree.ElementTree as ET
from typing import Any, Optional


def get_warning_url(xml_text: str) -> Optional[str]:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return None
    return root.findtext(".//WARNING/URL")


def _text(elem: Optional[ET.Element], tag: str) -> Optional[str]:
    if elem is None:
        return None
    val = elem.findtext(tag)
    return val if val else None


def _parse_tags(host_elem: ET.Element) -> list:
    return [t.findtext("NAME") or "" for t in host_elem.findall(".//TAGS/TAG")]


def _parse_cloud_tags(host_elem: ET.Element) -> list:
    tags = []
    for ct in host_elem.findall(".//CLOUD_TAG"):
        tags.append(
            {
                "name": ct.findtext("NAME"),
                "value": ct.findtext("VALUE"),
                "last_success_date": ct.findtext("LAST_SUCCESS_DATE"),
            }
        )
    return tags


def parse_host_detections(xml_text: str) -> list:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []

    events = []
    for host in root.findall(".//HOST_LIST/HOST"):
        host_data: dict[str, Any] = {
            "id": host.findtext("ID"),
            "ip": host.findtext("IP"),
            "ipv6": host.findtext("IPV6"),
            "dns": host.findtext("DNS"),
            "netbios": host.findtext("NETBIOS"),
            "os": host.findtext("OS"),
            "asset_id": host.findtext("ASSET_ID"),
            "tracking_method": host.findtext("TRACKING_METHOD"),
            "last_scan_datetime": host.findtext("LAST_SCAN_DATETIME"),
            "cloud_provider": host.findtext("CLOUD_PROVIDER"),
            "tags": _parse_tags(host),
            "cloud_tags": _parse_cloud_tags(host),
        }

        for detection in host.findall("DETECTION_LIST/DETECTION"):
            qds_factors: dict[str, Any] = {}
            for qf in detection.findall("QDS_FACTORS/QDS_FACTOR"):
                name = qf.get("name")
                if name:
                    qds_factors[name] = qf.text

            detection_data: dict[str, Any] = {
                "qid": detection.findtext("QID"),
                "type": detection.findtext("TYPE"),
                "severity": detection.findtext("SEVERITY"),
                "ssl": detection.findtext("SSL"),
                "results": detection.findtext("RESULTS"),
                "status": detection.findtext("STATUS"),
                "first_found": detection.findtext("FIRST_FOUND_DATETIME"),
                "last_found": detection.findtext("LAST_FOUND_DATETIME"),
                "times_found": detection.findtext("TIMES_FOUND"),
                "last_fixed": detection.findtext("LAST_FIXED_DATETIME"),
                "port": detection.findtext("PORT"),
                "protocol": detection.findtext("PROTOCOL"),
                "is_ignored": detection.findtext("IS_IGNORED"),
                "is_disabled": detection.findtext("IS_DISABLED"),
                "affect_running_kernel": detection.findtext("AFFECT_RUNNING_KERNEL"),
                "affect_running_service": detection.findtext("AFFECT_RUNNING_SERVICE"),
                "qds": detection.findtext("QDS"),
                "qds_factors": qds_factors,
            }

            events.append(
                {
                    "host": host_data,
                    "detection": detection_data,
                    "source": "qualys_vmdr",
                    "timestamp": detection_data.get("last_found") or "",
                }
            )

    return events


def parse_host_list(xml_text: str) -> list:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []

    hosts = []
    for host in root.findall(".//HOST_LIST/HOST"):
        hosts.append(
            {
                "id": host.findtext("ID"),
                "ip": host.findtext("IP"),
                "ipv6": host.findtext("IPV6"),
                "dns": host.findtext("DNS"),
                "netbios": host.findtext("NETBIOS"),
                "os": host.findtext("OS"),
                "tracking_method": host.findtext("TRACKING_METHOD"),
                "last_scan_datetime": host.findtext("LAST_SCAN_DATETIME"),
                "last_vm_scanned_date": host.findtext("LAST_VM_SCANNED_DATE"),
                "asset_group_ids": host.findtext("ASSET_GROUP_IDS"),
                "tags": _parse_tags(host),
            }
        )
    return hosts


def parse_knowledge_base(xml_text: str) -> list:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []

    vulns = []
    for vuln in root.findall(".//VULN_LIST/VULN"):
        cves = [cve.findtext("ID") for cve in vuln.findall(".//CVE_LIST/CVE") if cve.findtext("ID")]

        cvss_elem = vuln.find("CVSS")
        cvss_base = None
        if cvss_elem is not None:
            cvss_base = cvss_elem.findtext("BASE") or cvss_elem.findtext("BASE_OBJ")

        vulns.append(
            {
                "qid": vuln.findtext("QID"),
                "title": vuln.findtext("TITLE"),
                "vuln_type": vuln.findtext("VULN_TYPE"),
                "severity": vuln.findtext("SEVERITY_LEVEL"),
                "published_datetime": vuln.findtext("PUBLISHED_DATETIME"),
                "modified_datetime": vuln.findtext("MODIFIED_DATETIME"),
                "cves": cves,
                "cvss_base": cvss_base,
                "solution": vuln.findtext("SOLUTION"),
                "diagnosis": vuln.findtext("DIAGNOSIS"),
                "consequence": vuln.findtext("CONSEQUENCE"),
                "patch_available": vuln.findtext("PATCH_AVAILABLE"),
                "patch_published_date": vuln.findtext("LAST_CUSTOMIZATION"),
                "vendor_reference_list": [
                    vr.findtext("ID")
                    for vr in vuln.findall(".//VENDOR_REFERENCE_LIST/VENDOR_REFERENCE")
                    if vr.findtext("ID")
                ],
            }
        )
    return vulns


def parse_scan_launch(xml_text: str) -> dict:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return {}

    items: dict[str, Any] = {}
    for item in root.findall(".//ITEM_LIST/ITEM"):
        key = item.findtext("KEY")
        value = item.findtext("VALUE")
        if key and value:
            items[key] = value

    return {
        "scan_ref": items.get("REFERENCE", ""),
        "scan_id": items.get("ID", ""),
    }


def parse_scan_list(xml_text: str) -> list:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []

    scans = []
    for scan in root.findall(".//SCAN_LIST/SCAN"):
        status_elem = scan.find("STATUS")
        state = status_elem.findtext("STATE") if status_elem is not None else None

        scans.append(
            {
                "scan_ref": scan.findtext("REF"),
                "title": scan.findtext("TITLE"),
                "type": scan.findtext("TYPE"),
                "date": scan.findtext("DATE"),
                "duration": scan.findtext("DURATION"),
                "state": state,
                "target": scan.findtext("TARGET"),
                "user_login": scan.findtext("USER_LOGIN"),
                "processed": scan.findtext("PROCESSED"),
            }
        )
    return scans


def parse_scan_results(xml_text: str) -> list:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []

    results = []
    for host in root.findall(".//IP"):
        results.append(
            {
                "ip": host.get("value"),
                "name": host.get("name"),
                "os": host.findtext("OS"),
                "vulns": [
                    {
                        "number": cat.get("value"),
                        "qid": vuln.findtext("NUMBER") or vuln.get("number"),
                        "severity": vuln.findtext("SEVERITY") or vuln.get("severity"),
                        "title": vuln.findtext("TITLE") or vuln.get("title"),
                    }
                    for cat in host.findall(".//CAT")
                    for vuln in cat.findall("VULN")
                ],
            }
        )
    return results


def parse_asset_groups(xml_text: str) -> list:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []

    groups = []
    for ag in root.findall(".//ASSET_GROUP_LIST/ASSET_GROUP"):
        ips = [ip.text for ip in ag.findall(".//IP_SET/IP") if ip.text]
        ip_ranges = [r.text for r in ag.findall(".//IP_SET/IP_RANGE") if r.text]

        groups.append(
            {
                "id": ag.findtext("ID"),
                "title": ag.findtext("TITLE"),
                "description": ag.findtext("COMMENTS"),
                "ips": ips,
                "ip_ranges": ip_ranges,
                "owner_user_id": ag.findtext("OWNER_USER_ID"),
            }
        )
    return groups


def parse_activity_log(xml_text: str) -> list:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []

    entries = []
    for entry in root.findall(".//ACTIVITY_LOG_LIST/ACTIVITY_LOG"):
        entries.append(
            {
                "username": entry.findtext("USERNAME"),
                "action": entry.findtext("ACTION"),
                "datetime": entry.findtext("DATE"),
                "details": entry.findtext("DETAILS"),
                "module": entry.findtext("MODULE"),
            }
        )
    return entries


def parse_purge_response(xml_text: str) -> dict:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return {"purged_count": 0, "message": "Parse error"}

    text = root.findtext(".//RESPONSE/TEXT") or ""
    return {"purged_count": 0, "message": text}

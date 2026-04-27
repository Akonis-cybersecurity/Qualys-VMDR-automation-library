import unittest.mock as mock
from pathlib import Path

import pytest

from qualys_modules import QualysVMDRModule, QualysVMDRModuleConfiguration
from qualys_modules.actions.get_host_detections import GetHostDetectionsAction
from qualys_modules.actions.get_host_list import GetHostListAction
from qualys_modules.actions.get_vuln_by_cve import GetVulnByCVEAction
from qualys_modules.actions.launch_scan import LaunchVMScanAction
from qualys_modules.actions.query_knowledge_base import QueryKnowledgeBaseAction

from .conftest import HOST_DETECTION_XML, KNOWLEDGE_BASE_XML, SCAN_LAUNCH_XML

BASE_URL = "https://qualysapi.qualys.com"

HOST_LIST_XML = """<?xml version="1.0" encoding="UTF-8"?>
<HOST_LIST_OUTPUT>
  <RESPONSE>
    <HOST_LIST>
      <HOST>
        <ID>1</ID>
        <IP>10.0.0.1</IP>
        <TRACKING_METHOD>IP</TRACKING_METHOD>
        <OS><![CDATA[Linux]]></OS>
        <LAST_SCAN_DATETIME>2024-01-01T00:00:00Z</LAST_SCAN_DATETIME>
      </HOST>
      <HOST>
        <ID>2</ID>
        <IP>10.0.0.2</IP>
        <TRACKING_METHOD>DNS</TRACKING_METHOD>
        <OS><![CDATA[Windows]]></OS>
        <LAST_SCAN_DATETIME>2024-01-01T06:00:00Z</LAST_SCAN_DATETIME>
      </HOST>
    </HOST_LIST>
  </RESPONSE>
</HOST_LIST_OUTPUT>"""


def _make_module() -> QualysVMDRModule:
    module = QualysVMDRModule()
    module.configuration = QualysVMDRModuleConfiguration(
        base_url=BASE_URL,
        username="user",
        password="pass",
    )
    return module


def _make_action(action_class, symphony_storage: Path):
    module = _make_module()
    action = action_class(data_path=symphony_storage)
    action.module = module
    return action


def test_get_host_detections_with_mock_xml(symphony_storage, requests_mock):
    action = _make_action(GetHostDetectionsAction, symphony_storage)

    requests_mock.get(
        f"{BASE_URL}/api/2.0/fo/asset/host/vm/detection/",
        text=HOST_DETECTION_XML,
    )

    result = action.run({})

    assert "detections" in result
    assert "total_detections" in result
    assert "total_hosts" in result
    assert result["total_detections"] == 1
    assert result["detections"][0]["detection"]["qid"] == "90007"
    assert result["detections"][0]["host"]["ip"] == "192.168.1.1"


def test_get_host_list_with_mock_xml(symphony_storage, requests_mock):
    action = _make_action(GetHostListAction, symphony_storage)

    requests_mock.get(
        f"{BASE_URL}/api/2.0/fo/asset/host/",
        text=HOST_LIST_XML,
    )

    result = action.run({})

    assert "hosts" in result
    assert result["total"] == 2
    assert result["hosts"][0]["ip"] == "10.0.0.1"


def test_query_knowledge_base_uses_v3_endpoint(symphony_storage, requests_mock):
    action = _make_action(QueryKnowledgeBaseAction, symphony_storage)

    requests_mock.get(
        f"{BASE_URL}/api/3.0/fo/knowledge_base/vuln/",
        text=KNOWLEDGE_BASE_XML,
    )

    result = action.run({})

    assert "vulnerabilities" in result
    assert result["total"] == 1
    assert requests_mock.last_request.url.startswith(f"{BASE_URL}/api/3.0/fo/knowledge_base/vuln/")


def test_query_knowledge_base_parses_cves(symphony_storage, requests_mock):
    action = _make_action(QueryKnowledgeBaseAction, symphony_storage)

    requests_mock.get(
        f"{BASE_URL}/api/3.0/fo/knowledge_base/vuln/",
        text=KNOWLEDGE_BASE_XML,
    )

    result = action.run({})

    vuln = result["vulnerabilities"][0]
    assert "CVE-2024-12345" in vuln["cves"]
    assert vuln["qid"] == "90007"


def test_get_vuln_by_cve_extracts_qids(symphony_storage, requests_mock):
    action = _make_action(GetVulnByCVEAction, symphony_storage)

    requests_mock.get(
        f"{BASE_URL}/api/3.0/fo/knowledge_base/vuln/",
        text=KNOWLEDGE_BASE_XML,
    )

    result = action.run({"cve_id": "CVE-2024-12345"})

    assert "qids" in result
    assert "vulnerabilities" in result
    assert 90007 in result["qids"]
    assert requests_mock.last_request.qs.get("cve_id") == ["cve-2024-12345"]


def test_launch_scan_extracts_scan_ref(symphony_storage, requests_mock):
    action = _make_action(LaunchVMScanAction, symphony_storage)

    requests_mock.post(
        f"{BASE_URL}/api/2.0/fo/scan/",
        text=SCAN_LAUNCH_XML,
    )

    result = action.run({"scan_title": "Test Scan", "ips": "192.168.1.0/24"})

    assert result["scan_ref"] == "scan/1234567890.12345"
    assert result["scan_id"] == "12345678"


def test_launch_scan_sends_post(symphony_storage, requests_mock):
    action = _make_action(LaunchVMScanAction, symphony_storage)

    requests_mock.post(
        f"{BASE_URL}/api/2.0/fo/scan/",
        text=SCAN_LAUNCH_XML,
    )

    action.run({"scan_title": "My Scan"})

    assert requests_mock.last_request.method == "POST"

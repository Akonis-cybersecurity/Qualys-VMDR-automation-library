from pathlib import Path
from shutil import rmtree
from tempfile import mkdtemp

import pytest
from sekoia_automation import constants


@pytest.fixture
def symphony_storage():
    original_storage = constants.DATA_STORAGE
    constants.DATA_STORAGE = mkdtemp()
    yield Path(constants.DATA_STORAGE)
    rmtree(constants.DATA_STORAGE)
    constants.DATA_STORAGE = original_storage


HOST_DETECTION_XML = """<?xml version="1.0" encoding="UTF-8"?>
<HOST_LIST_VM_DETECTION_OUTPUT>
  <RESPONSE>
    <DATETIME>2024-01-01T00:00:00Z</DATETIME>
    <HOST_LIST>
      <HOST>
        <ID>12345</ID>
        <IP>192.168.1.1</IP>
        <TRACKING_METHOD>IP</TRACKING_METHOD>
        <OS><![CDATA[Windows Server 2019]]></OS>
        <DNS><![CDATA[server01.example.com]]></DNS>
        <LAST_SCAN_DATETIME>2024-01-01T00:00:00Z</LAST_SCAN_DATETIME>
        <DETECTION_LIST>
          <DETECTION>
            <QID>90007</QID>
            <TYPE>Confirmed</TYPE>
            <SEVERITY>5</SEVERITY>
            <RESULTS><![CDATA[some results]]></RESULTS>
            <STATUS>Active</STATUS>
            <FIRST_FOUND_DATETIME>2024-01-01T00:00:00Z</FIRST_FOUND_DATETIME>
            <LAST_FOUND_DATETIME>2024-01-02T00:00:00Z</LAST_FOUND_DATETIME>
            <TIMES_FOUND>5</TIMES_FOUND>
            <IS_IGNORED>0</IS_IGNORED>
            <IS_DISABLED>0</IS_DISABLED>
            <QDS>60</QDS>
            <QDS_FACTORS>
              <QDS_FACTOR name="cvss">7.5</QDS_FACTOR>
            </QDS_FACTORS>
          </DETECTION>
        </DETECTION_LIST>
      </HOST>
    </HOST_LIST>
  </RESPONSE>
</HOST_LIST_VM_DETECTION_OUTPUT>"""

HOST_DETECTION_XML_WITH_WARNING = """<?xml version="1.0" encoding="UTF-8"?>
<HOST_LIST_VM_DETECTION_OUTPUT>
  <RESPONSE>
    <HOST_LIST>
      <HOST>
        <ID>99</ID>
        <IP>10.0.0.1</IP>
        <DETECTION_LIST>
          <DETECTION>
            <QID>11111</QID>
            <TYPE>Confirmed</TYPE>
            <SEVERITY>3</SEVERITY>
            <STATUS>New</STATUS>
            <FIRST_FOUND_DATETIME>2024-01-01T00:00:00Z</FIRST_FOUND_DATETIME>
            <LAST_FOUND_DATETIME>2024-01-01T06:00:00Z</LAST_FOUND_DATETIME>
            <TIMES_FOUND>1</TIMES_FOUND>
            <IS_IGNORED>0</IS_IGNORED>
            <IS_DISABLED>0</IS_DISABLED>
          </DETECTION>
        </DETECTION_LIST>
      </HOST>
    </HOST_LIST>
    <WARNING>
      <CODE>1980</CODE>
      <TEXT>1000 record limit reached</TEXT>
      <URL><![CDATA[https://qualysapi.qualys.com/api/2.0/fo/asset/host/vm/detection/?action=list&id_min=100]]></URL>
    </WARNING>
  </RESPONSE>
</HOST_LIST_VM_DETECTION_OUTPUT>"""

KNOWLEDGE_BASE_XML = """<?xml version="1.0" encoding="UTF-8"?>
<KNOWLEDGE_BASE_VULN_LIST_OUTPUT>
  <RESPONSE>
    <VULN_LIST>
      <VULN>
        <QID>90007</QID>
        <VULN_TYPE>Confirmed</VULN_TYPE>
        <SEVERITY_LEVEL>5</SEVERITY_LEVEL>
        <TITLE><![CDATA[OS Detected]]></TITLE>
        <PUBLISHED_DATETIME>2005-01-01T00:00:00Z</PUBLISHED_DATETIME>
        <CVE_LIST>
          <CVE>
            <ID>CVE-2024-12345</ID>
            <URL>https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-12345</URL>
          </CVE>
        </CVE_LIST>
        <CVSS>
          <BASE>7.5</BASE>
        </CVSS>
        <SOLUTION><![CDATA[Apply patch]]></SOLUTION>
        <DIAGNOSIS><![CDATA[Vulnerability details]]></DIAGNOSIS>
        <PATCH_AVAILABLE>1</PATCH_AVAILABLE>
      </VULN>
    </VULN_LIST>
  </RESPONSE>
</KNOWLEDGE_BASE_VULN_LIST_OUTPUT>"""

SCAN_LAUNCH_XML = """<?xml version="1.0" encoding="UTF-8"?>
<SIMPLE_RETURN>
  <RESPONSE>
    <DATETIME>2024-01-01T00:00:00Z</DATETIME>
    <TEXT>New scan launched</TEXT>
    <ITEM_LIST>
      <ITEM>
        <KEY>ID</KEY>
        <VALUE>12345678</VALUE>
      </ITEM>
      <ITEM>
        <KEY>REFERENCE</KEY>
        <VALUE>scan/1234567890.12345</VALUE>
      </ITEM>
    </ITEM_LIST>
  </RESPONSE>
</SIMPLE_RETURN>"""

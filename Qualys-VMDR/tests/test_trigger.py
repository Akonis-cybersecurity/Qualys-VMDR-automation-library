import json
import unittest.mock as mock
from pathlib import Path

import pytest

from qualys_modules import QualysVMDRModule, QualysVMDRModuleConfiguration
from qualys_modules.trigger_host_detections import QualysVMDRTrigger, QualysVMDRTriggerConfiguration

from .conftest import HOST_DETECTION_XML, HOST_DETECTION_XML_WITH_WARNING

BASE_URL = "https://qualysapi.qualys.com"


def _make_trigger(symphony_storage: Path) -> QualysVMDRTrigger:
    module = QualysVMDRModule()
    module.configuration = QualysVMDRModuleConfiguration(
        base_url=BASE_URL,
        username="user",
        password="pass",
    )
    trigger = QualysVMDRTrigger(data_path=symphony_storage)
    trigger.module = module
    trigger.configuration = QualysVMDRTriggerConfiguration(
        intake_key="test-intake-key",
        frequency=3600,
        chunk_lookback_hours=1,
    )
    return trigger


def test_trigger_fetch_with_mock_xml(symphony_storage, requests_mock):
    trigger = _make_trigger(symphony_storage)

    requests_mock.get(
        f"{BASE_URL}/api/2.0/fo/asset/host/vm/detection/",
        text=HOST_DETECTION_XML,
    )

    events = trigger.fetch_detections(trigger._build_client(), "2024-01-01T00:00:00Z")

    assert len(events) == 1
    assert events[0]["host"]["ip"] == "192.168.1.1"
    assert events[0]["detection"]["qid"] == "90007"
    assert events[0]["source"] == "qualys_vmdr"


def test_trigger_pagination_stops_without_warning(symphony_storage, requests_mock):
    trigger = _make_trigger(symphony_storage)

    requests_mock.get(
        f"{BASE_URL}/api/2.0/fo/asset/host/vm/detection/",
        text=HOST_DETECTION_XML,
    )

    events = trigger.fetch_detections(trigger._build_client(), "2024-01-01T00:00:00Z")
    assert requests_mock.call_count == 1
    assert len(events) == 1


def test_trigger_pagination_follows_warning_url(symphony_storage, requests_mock):
    trigger = _make_trigger(symphony_storage)

    continuation_url = f"{BASE_URL}/api/2.0/fo/asset/host/vm/detection/?action=list&id_min=100"

    requests_mock.get(
        f"{BASE_URL}/api/2.0/fo/asset/host/vm/detection/",
        text=HOST_DETECTION_XML_WITH_WARNING,
    )
    requests_mock.get(continuation_url, text=HOST_DETECTION_XML)

    events = trigger.fetch_detections(trigger._build_client(), "2024-01-01T00:00:00Z")

    assert len(events) == 2


def test_trigger_cursor_passed_as_param(symphony_storage, requests_mock):
    trigger = _make_trigger(symphony_storage)

    requests_mock.get(
        f"{BASE_URL}/api/2.0/fo/asset/host/vm/detection/",
        text=HOST_DETECTION_XML,
    )

    trigger.fetch_detections(trigger._build_client(), "2024-06-01T12:00:00Z")

    qs_val = requests_mock.last_request.qs.get("detection_updated_since", [])
    assert qs_val and qs_val[0].lower() == "2024-06-01t12:00:00z"


def test_trigger_push_events_to_intakes_called(symphony_storage, requests_mock):
    trigger = _make_trigger(symphony_storage)

    requests_mock.get(
        f"{BASE_URL}/api/2.0/fo/asset/host/vm/detection/",
        text=HOST_DETECTION_XML,
    )

    with mock.patch.object(trigger, "push_events_to_intakes", return_value=["event-id-1"]) as mock_push:
        events_dicts = trigger.fetch_detections(trigger._build_client(), "2024-01-01T00:00:00Z")
        events_json = [json.dumps(e) for e in events_dicts]
        trigger.push_events_to_intakes(events=events_json)

        mock_push.assert_called_once()
        call_kwargs = mock_push.call_args
        events = call_kwargs[1].get("events") or call_kwargs[0][0]
        assert len(events) == 1
        parsed = json.loads(events[0])
        assert parsed["host"]["ip"] == "192.168.1.1"


def test_trigger_cursor_default_uses_lookback(symphony_storage):
    trigger = _make_trigger(symphony_storage)
    cursor = trigger.cursor
    assert "T" in cursor
    assert cursor.endswith("Z")


def test_trigger_cursor_persisted_after_run(symphony_storage, requests_mock):
    trigger = _make_trigger(symphony_storage)

    requests_mock.get(
        f"{BASE_URL}/api/2.0/fo/asset/host/vm/detection/",
        text=HOST_DETECTION_XML,
    )

    with mock.patch.object(trigger, "push_events_to_intakes", return_value=["id"]):
        events = trigger.fetch_detections(trigger._build_client(), "2024-01-01T00:00:00Z")
        timestamps = [e["detection"]["last_found"] for e in events if e["detection"].get("last_found")]
        if timestamps:
            with trigger.context as cache:
                cache["last_event_datetime"] = max(timestamps)

    assert trigger.cursor == "2024-01-02T00:00:00Z"

import json
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sekoia_automation.connector import Connector, DefaultConnectorConfiguration
from sekoia_automation.storage import PersistentJSON

from qualys_modules import QualysVMDRModule
from qualys_modules.client import QualysClient
from qualys_modules.parsers import get_warning_url, parse_host_detections


class QualysVMDRTriggerConfiguration(DefaultConnectorConfiguration):
    frequency: int = 3600
    chunk_lookback_hours: int = 1


class QualysVMDRTrigger(Connector):
    module: QualysVMDRModule
    configuration: QualysVMDRTriggerConfiguration

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.context = PersistentJSON("context.json", self._data_path)

    @property
    def cursor(self) -> str:
        with self.context as cache:
            cursor: Optional[str] = cache.get("last_event_datetime")
        if cursor is None:
            lookback = timedelta(hours=self.configuration.chunk_lookback_hours)
            cursor = (datetime.now(timezone.utc) - lookback).strftime("%Y-%m-%dT%H:%M:%SZ")
        return cursor

    def _build_client(self) -> QualysClient:
        cfg = self.module.configuration
        return QualysClient(cfg.base_url, cfg.username, cfg.password)

    def fetch_detections(self, client: QualysClient, since: str) -> list:
        endpoint = "/api/2.0/fo/asset/host/vm/detection/"
        params: dict = {
            "action": "list",
            "detection_updated_since": since,
            "truncation_limit": 1000,
            "include_vuln_type": "confirmed",
            "show_qds": 1,
            "show_qds_factors": 1,
            "show_tags": 1,
            "show_asset_id": 1,
            "host_metadata": "all",
            "show_cloud_tags": 1,
            "filter_superseded_qids": 1,
        }

        events = []
        while True:
            xml_text = client.get(endpoint, params=params)
            batch = parse_host_detections(xml_text)
            events.extend(batch)
            warning_url = get_warning_url(xml_text)
            if not warning_url:
                break
            endpoint = warning_url
            params = {}

        return events

    def run(self) -> None:
        self.log(message="QualysVMDRTrigger started", level="info")
        client = self._build_client()

        while self.running:
            start = time.time()
            since = self.cursor

            try:
                events = self.fetch_detections(client, since)

                if events:
                    events_json = [json.dumps(event) for event in events]
                    self.push_events_to_intakes(events=events_json)

                    timestamps = [
                        e["detection"]["last_found"]
                        for e in events
                        if e.get("detection", {}).get("last_found")
                    ]
                    if timestamps:
                        new_cursor = max(timestamps)
                        with self.context as cache:
                            cache["last_event_datetime"] = new_cursor

                    self.log(message=f"Pushed {len(events)} events to intake", level="info")
                else:
                    self.log(message="No new detections found", level="info")

            except Exception as ex:
                self.log_exception(ex, message="Error fetching Qualys VMDR detections")

            duration = time.time() - start
            sleep_time = self.configuration.frequency - duration
            if sleep_time > 0:
                time.sleep(sleep_time)

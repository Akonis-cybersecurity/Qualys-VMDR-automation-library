from sekoia_automation.action import Action

from qualys_modules import QualysVMDRModule
from qualys_modules.client import QualysClient
from qualys_modules.parsers import get_warning_url, parse_host_detections


class GetHostDetectionsAction(Action):
    module: QualysVMDRModule

    def run(self, arguments: dict) -> dict:
        cfg = self.module.configuration
        client = QualysClient(cfg.base_url, cfg.username, cfg.password)

        params: dict = {"action": "list"}
        if arguments.get("host_ids"):
            params["ids"] = arguments["host_ids"]
        if arguments.get("ips"):
            params["ips"] = arguments["ips"]
        params["include_vuln_type"] = arguments.get("include_vuln_type", "confirmed")
        if arguments.get("status"):
            params["status"] = arguments["status"]
        if arguments.get("severity"):
            params["severities"] = arguments["severity"]
        params["show_qds"] = 1
        params["show_qds_factors"] = 1
        params["show_tags"] = 1
        params["show_asset_id"] = 1
        params["truncation_limit"] = 1000

        endpoint = "/api/2.0/fo/asset/host/vm/detection/"
        detections = []
        hosts_seen: set = set()

        while True:
            xml = client.get(endpoint, params=params)
            batch = parse_host_detections(xml)
            detections.extend(batch)
            for event in batch:
                host_id = event.get("host", {}).get("id")
                if host_id:
                    hosts_seen.add(host_id)
            warning_url = get_warning_url(xml)
            if not warning_url:
                break
            endpoint = warning_url
            params = {}

        return {
            "detections": detections,
            "total_hosts": len(hosts_seen),
            "total_detections": len(detections),
        }

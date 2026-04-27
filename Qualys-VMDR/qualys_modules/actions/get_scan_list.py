from sekoia_automation.action import Action

from qualys_modules import QualysVMDRModule
from qualys_modules.client import QualysClient
from qualys_modules.parsers import get_warning_url, parse_scan_list


class GetScanListAction(Action):
    module: QualysVMDRModule

    def run(self, arguments: dict) -> dict:
        cfg = self.module.configuration
        client = QualysClient(cfg.base_url, cfg.username, cfg.password)

        params: dict = {"action": "list"}
        if arguments.get("state"):
            params["state"] = arguments["state"]
        if arguments.get("scan_ref"):
            params["scan_ref"] = arguments["scan_ref"]
        if arguments.get("launched_after_datetime"):
            params["launched_after_datetime"] = arguments["launched_after_datetime"]

        endpoint = "/api/2.0/fo/scan/"
        scans = []

        while True:
            xml = client.get(endpoint, params=params)
            batch = parse_scan_list(xml)
            scans.extend(batch)
            warning_url = get_warning_url(xml)
            if not warning_url:
                break
            endpoint = warning_url
            params = {}

        return {"scans": scans, "total": len(scans)}

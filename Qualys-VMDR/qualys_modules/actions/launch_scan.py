from sekoia_automation.action import Action

from qualys_modules import QualysVMDRModule
from qualys_modules.client import QualysClient
from qualys_modules.parsers import parse_scan_launch


class LaunchVMScanAction(Action):
    module: QualysVMDRModule

    def run(self, arguments: dict) -> dict:
        cfg = self.module.configuration
        client = QualysClient(cfg.base_url, cfg.username, cfg.password)

        data: dict = {
            "action": "launch",
            "scan_title": arguments["scan_title"],
        }
        if arguments.get("ips"):
            data["ip"] = arguments["ips"]
        if arguments.get("asset_group_ids"):
            data["asset_group_ids"] = arguments["asset_group_ids"]
        if arguments.get("option_id"):
            data["option_id"] = arguments["option_id"]
        if arguments.get("option_title"):
            data["option_title"] = arguments["option_title"]

        xml = client.post("/api/2.0/fo/scan/", data=data)
        return parse_scan_launch(xml)

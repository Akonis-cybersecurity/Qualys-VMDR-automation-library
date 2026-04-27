from sekoia_automation.action import Action

from qualys_modules import QualysVMDRModule
from qualys_modules.client import QualysClient
from qualys_modules.parsers import parse_purge_response


class PurgeHostsAction(Action):
    module: QualysVMDRModule

    def run(self, arguments: dict) -> dict:
        cfg = self.module.configuration
        client = QualysClient(cfg.base_url, cfg.username, cfg.password)

        if not arguments.get("ids") and not arguments.get("ips"):
            raise ValueError("At least one of 'ids' or 'ips' must be provided")

        data: dict = {"action": "purge"}
        if arguments.get("ids"):
            data["ids"] = arguments["ids"]
        if arguments.get("ips"):
            data["ips"] = arguments["ips"]

        xml = client.post("/api/2.0/fo/asset/host/", data=data)
        return parse_purge_response(xml)

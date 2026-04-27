from sekoia_automation.action import Action

from qualys_modules import QualysVMDRModule
from qualys_modules.client import QualysClient
from qualys_modules.parsers import get_warning_url, parse_host_list


class GetHostListAction(Action):
    module: QualysVMDRModule

    def run(self, arguments: dict) -> dict:
        cfg = self.module.configuration
        client = QualysClient(cfg.base_url, cfg.username, cfg.password)

        params: dict = {"action": "list"}
        if arguments.get("ids"):
            params["ids"] = arguments["ids"]
        if arguments.get("ips"):
            params["ips"] = arguments["ips"]
        params["details"] = arguments.get("details", "All")
        params["truncation_limit"] = 1000

        endpoint = "/api/2.0/fo/asset/host/"
        hosts = []

        while True:
            xml = client.get(endpoint, params=params)
            batch = parse_host_list(xml)
            hosts.extend(batch)
            warning_url = get_warning_url(xml)
            if not warning_url:
                break
            endpoint = warning_url
            params = {}

        return {"hosts": hosts, "total": len(hosts)}

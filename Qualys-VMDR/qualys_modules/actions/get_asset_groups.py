from sekoia_automation.action import Action

from qualys_modules import QualysVMDRModule
from qualys_modules.client import QualysClient
from qualys_modules.parsers import get_warning_url, parse_asset_groups


class GetAssetGroupsAction(Action):
    module: QualysVMDRModule

    def run(self, arguments: dict) -> dict:
        cfg = self.module.configuration
        client = QualysClient(cfg.base_url, cfg.username, cfg.password)

        params: dict = {"action": "list"}
        if arguments.get("ids"):
            params["ids"] = arguments["ids"]
        if arguments.get("title_contains"):
            params["title"] = arguments["title_contains"]

        endpoint = "/api/2.0/fo/asset/group/"
        asset_groups = []

        while True:
            xml = client.get(endpoint, params=params)
            batch = parse_asset_groups(xml)
            asset_groups.extend(batch)
            warning_url = get_warning_url(xml)
            if not warning_url:
                break
            endpoint = warning_url
            params = {}

        return {"asset_groups": asset_groups, "total": len(asset_groups)}

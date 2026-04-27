from sekoia_automation.action import Action

from qualys_modules import QualysVMDRModule
from qualys_modules.client import QualysClient
from qualys_modules.parsers import get_warning_url, parse_activity_log


class GetActivityLogAction(Action):
    module: QualysVMDRModule

    def run(self, arguments: dict) -> dict:
        cfg = self.module.configuration
        client = QualysClient(cfg.base_url, cfg.username, cfg.password)

        params: dict = {"action": "list"}
        if arguments.get("username"):
            params["user_login"] = arguments["username"]
        if arguments.get("since_datetime"):
            params["since_datetime"] = arguments["since_datetime"]
        if arguments.get("until_datetime"):
            params["until_datetime"] = arguments["until_datetime"]
        params["truncation_limit"] = 1000

        endpoint = "/api/2.0/fo/activity_log/"
        log_entries = []

        while True:
            xml = client.get(endpoint, params=params)
            batch = parse_activity_log(xml)
            log_entries.extend(batch)
            warning_url = get_warning_url(xml)
            if not warning_url:
                break
            endpoint = warning_url
            params = {}

        return {"log_entries": log_entries, "total": len(log_entries)}

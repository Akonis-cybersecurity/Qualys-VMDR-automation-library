from sekoia_automation.action import Action

from qualys_modules import QualysVMDRModule
from qualys_modules.client import QualysClient
from qualys_modules.parsers import get_warning_url, parse_knowledge_base


class QueryKnowledgeBaseAction(Action):
    module: QualysVMDRModule

    def run(self, arguments: dict) -> dict:
        cfg = self.module.configuration
        client = QualysClient(cfg.base_url, cfg.username, cfg.password)

        params: dict = {"action": "list"}
        if arguments.get("ids"):
            params["ids"] = arguments["ids"]
        params["details"] = arguments.get("details", "All")
        if arguments.get("published_after"):
            params["published_after_datetime"] = arguments["published_after"]
        if arguments.get("published_before"):
            params["published_before_datetime"] = arguments["published_before"]
        if arguments.get("cvss_base_min") is not None:
            params["min_cvss_base"] = arguments["cvss_base_min"]
        params["truncation_limit"] = 1000

        endpoint = "/api/3.0/fo/knowledge_base/vuln/"
        vulnerabilities = []

        while True:
            xml = client.get(endpoint, params=params)
            batch = parse_knowledge_base(xml)
            vulnerabilities.extend(batch)
            warning_url = get_warning_url(xml)
            if not warning_url:
                break
            endpoint = warning_url
            params = {}

        return {"vulnerabilities": vulnerabilities, "total": len(vulnerabilities)}

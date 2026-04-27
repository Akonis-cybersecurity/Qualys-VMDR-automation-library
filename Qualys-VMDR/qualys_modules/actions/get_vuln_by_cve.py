from sekoia_automation.action import Action

from qualys_modules import QualysVMDRModule
from qualys_modules.client import QualysClient
from qualys_modules.parsers import get_warning_url, parse_knowledge_base


class GetVulnByCVEAction(Action):
    module: QualysVMDRModule

    def run(self, arguments: dict) -> dict:
        cfg = self.module.configuration
        client = QualysClient(cfg.base_url, cfg.username, cfg.password)

        cve_id: str = arguments["cve_id"]
        params: dict = {
            "action": "list",
            "details": "All",
            "cve_id": cve_id,
            "truncation_limit": 1000,
        }

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

        qids = [int(v["qid"]) for v in vulnerabilities if v.get("qid")]

        return {"qids": qids, "vulnerabilities": vulnerabilities}

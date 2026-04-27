from sekoia_automation.action import Action

from qualys_modules import QualysVMDRModule
from qualys_modules.client import QualysClient
from qualys_modules.parsers import parse_scan_results


class GetScanResultsAction(Action):
    module: QualysVMDRModule

    def run(self, arguments: dict) -> dict:
        cfg = self.module.configuration
        client = QualysClient(cfg.base_url, cfg.username, cfg.password)

        params = {"action": "fetch", "scan_ref": arguments["scan_ref"]}
        xml = client.get("/api/2.0/fo/scan/", params=params)
        results = parse_scan_results(xml)

        return {"results": results, "host_count": len(results)}

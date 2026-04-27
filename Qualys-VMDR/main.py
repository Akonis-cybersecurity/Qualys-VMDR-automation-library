from qualys_modules import QualysVMDRModule
from qualys_modules.actions.get_activity_log import GetActivityLogAction
from qualys_modules.actions.get_asset_groups import GetAssetGroupsAction
from qualys_modules.actions.get_host_detections import GetHostDetectionsAction
from qualys_modules.actions.get_host_list import GetHostListAction
from qualys_modules.actions.get_scan_list import GetScanListAction
from qualys_modules.actions.get_scan_results import GetScanResultsAction
from qualys_modules.actions.get_vuln_by_cve import GetVulnByCVEAction
from qualys_modules.actions.launch_scan import LaunchVMScanAction
from qualys_modules.actions.purge_hosts import PurgeHostsAction
from qualys_modules.actions.query_knowledge_base import QueryKnowledgeBaseAction
from qualys_modules.trigger_host_detections import QualysVMDRTrigger

if __name__ == "__main__":
    module = QualysVMDRModule()
    module.register(QualysVMDRTrigger, "qualys_vmdr_trigger")
    module.register(GetHostDetectionsAction, "qualys_get_host_detections")
    module.register(GetHostListAction, "qualys_get_host_list")
    module.register(QueryKnowledgeBaseAction, "qualys_query_knowledge_base")
    module.register(GetVulnByCVEAction, "qualys_get_vuln_by_cve")
    module.register(LaunchVMScanAction, "qualys_launch_scan")
    module.register(GetScanListAction, "qualys_get_scan_list")
    module.register(GetScanResultsAction, "qualys_get_scan_results")
    module.register(GetAssetGroupsAction, "qualys_get_asset_groups")
    module.register(GetActivityLogAction, "qualys_get_activity_log")
    module.register(PurgeHostsAction, "qualys_purge_hosts")
    module.run()

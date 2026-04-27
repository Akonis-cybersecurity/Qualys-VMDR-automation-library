# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 2026-04-27 - 1.0.0

### Added
- Initial release of Qualys VMDR connector
- Trigger `QualysVMDRTrigger` to collect host detections from Qualys VMDR API v2
- Action `GetHostDetections` to query host vulnerability detections
- Action `GetHostList` to list assets from Qualys inventory
- Action `QueryKnowledgeBase` to search Qualys vulnerability knowledge base (API v3)
- Action `GetVulnByCVE` to find Qualys QIDs matching a given CVE identifier
- Action `LaunchVMScan` to launch a new vulnerability scan
- Action `GetScanList` to list existing scans
- Action `GetScanResults` to fetch results of a completed scan
- Action `GetAssetGroups` to list asset groups
- Action `GetActivityLog` to retrieve the Qualys activity log
- Action `PurgeHosts` to purge host records from Qualys

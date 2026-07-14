# Changes (Final Product Delta vs. Origin)

## Scope
This document summarizes the final functional product changes introduced in the current work compared to the original baseline.
It focuses on runtime behavior and report output (not only tests).

## 1) TamemyCert integration for template findings
### What was added
- Added TamemyCert enrichment for certificate template findings.
- New utility function resolves TamemyCert XML policy per template by file name:
  - Match rule: XML base name == Template `Name`
  - Source folder: `tamemycertxml`
  - If multiple files match, the newest file (`LastWriteTime`) is used.

### New runtime fields on findings
Template issues now include:
- `TamemyCertHardening` (bool)
- `TamemyCertHardeningXmlName` (string)
- `TamemyCertHardeningSummary` (string)

### Behavior
- If no matching XML exists: `TamemyCertHardening = False` and summary explains missing file.
- If XML exists and can be parsed: `TamemyCertHardening = True`, XML file name is set, and summary is generated.
- If XML exists but is invalid: summary indicates parse/root-element error.

### Files
- `Private/Utility/Get-TamemyCertHardening.ps1` (new)
- `Classes/LS2Issue.ps1`
- `Public/Find-LS2VulnerableTemplate.ps1`

## 2) TamemyCert summary quality improvements
### What was improved
The summary now describes multiple hardening measures, not only subject/SAN regex rules.

### Included in summary
- `AuditOnly` status
- Subject/SubjectAlternativeName rules:
  - field name
  - mandatory flag
  - max occurrences (if present)
  - all regex expressions
- DirectoryServicesMapping controls (if present):
  - `SearchRoot`
  - allowed security groups
  - disallowed security groups

### Files
- `Private/Utility/Get-TamemyCertHardening.ps1`

## 3) Report output changes (console + dashboard)
### Console report (`Show-IssueReport`)
For template techniques, output now includes separate report fields:
- `TamemyCertHardening`
- `TamemyCertHardeningXmlName`
- `TamemyCertHardeningSummary`

Important: `TamemyCertHardening` remains a pure `True/False` value to support filtering.

### HTML dashboard (`New-LS2Dashboard`)
Dashboard table projection now separates:
- `TamemyCertHardening` (boolean-like value)
- `TamemyCertHardeningXmlName` (separate column)
- `TamemyCertHardeningSummary`

### Files
- `Private/UI/Show-IssueReport.ps1`
- `Public/New-LS2Dashboard.ps1`

## 4) Resilience fix: CA disable extension list
### What was fixed
`Set-CADisableExtensionList` no longer hard-fails when PSCertutil cmdlet `Get-PSCDisableExtensionList` is unavailable.

### New behavior
- Emits warning and continues scan.
- Applies safe defaults:
  - `DisableExtensionList = @()`
  - `SecurityExtensionDisabled = $false`
- Uses defensive property assignment to avoid missing-property runtime errors.

### Files
- `Private/Set/Set-CADisableExtensionList.ps1`

## 5) Product assets/config added
### Added sample export artifact
- `sample.xml`

## 6) Test updates (verification coverage)
The following tests were added/updated to cover the new behavior:
- `Tests/Private/Utility/Get-TamemyCertHardening.Tests.ps1` (new)
- `Tests/Public/Find-LS2VulnerableTemplate.Tests.ps1`
- `Tests/Private/UI/Show-IssueReport.Tests.ps1`
- `Tests/Public/New-LS2Dashboard.Tests.ps1`
- `Tests/Private/Set/Set-CADisableExtensionList.Tests.ps1`
- `Tests/Shared/TestHelpers.psm1`

## 7) Operational note
When validating renamed/new TamemyCert XML files, run a fresh scan with rescan enabled to avoid stale `IssueStore` data:
- `Invoke-Locksmith2 -Mode 1 -Rescan -SkipPowerShellCheck -Force`

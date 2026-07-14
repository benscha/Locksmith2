function Get-TamemyCertHardening {
    <#
        .SYNOPSIS
        Returns TamemyCert hardening details for a certificate template.

        .DESCRIPTION
        Looks up the newest TamemyCert XML policy file whose name matches the template name,
        parses the hardening rules, and returns a small reporting object.

        .PARAMETER TemplateName
        Certificate template name used to match the XML file name without the .xml extension.

        .OUTPUTS
        PSCustomObject
        Returns TamemyCertHardening and TamemyCertHardeningSummary properties.

        .NOTES
        Author: GitHub Copilot
        Module: Locksmith2
        Requires: PowerShell 5.1+
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [string]$TemplateName
    )

    $moduleRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $tamemyCertPath = Join-Path $moduleRoot 'tamemycertxml'

    $result = [PSCustomObject]@{
        TamemyCertHardening        = $false
        TamemyCertHardeningXmlName = $null
        TamemyCertHardeningSummary = 'No TamemyCert XML was found for this template.'
    }

    if (-not (Test-Path -LiteralPath $tamemyCertPath)) {
        return $result
    }

    $policyFile = Get-ChildItem -LiteralPath $tamemyCertPath -Filter '*.xml' -File -ErrorAction SilentlyContinue |
    Where-Object { $_.BaseName -eq $TemplateName } |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1

    if (-not $policyFile) {
        return $result
    }

    $result.TamemyCertHardeningXmlName = $policyFile.Name

    try {
        [xml]$policyDocument = Get-Content -LiteralPath $policyFile.FullName -Raw -ErrorAction Stop
    }
    catch {
        $result.TamemyCertHardeningSummary = 'TamemyCert XML was found but could not be parsed.'
        return $result
    }

    $policyRoot = $policyDocument.CertificateRequestPolicy
    if (-not $policyRoot) {
        $result.TamemyCertHardeningSummary = 'TamemyCert XML was found but did not contain a CertificateRequestPolicy root element.'
        return $result
    }

    $summaryLines = New-Object System.Collections.Generic.List[string]

    function Add-SummaryLine {
        param(
            [Parameter(Mandatory)]
            [string]$Text
        )

        if (-not [string]::IsNullOrWhiteSpace($Text)) {
            $summaryLines.Add($Text)
        }
    }

    function Convert-FieldLabel {
        param([string]$Name)

        if ([string]::IsNullOrWhiteSpace($Name)) {
            return $Name
        }

        return ($Name.Substring(0, 1).ToUpperInvariant() + $Name.Substring(1))
    }

    function Get-NonEmptyStrings {
        param([object[]]$Values)

        return @($Values | ForEach-Object { [string]$_ } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    }

    function Convert-ToNullableBooleanText {
        param([object]$Value)

        $textValue = [string]$Value
        if ([string]::IsNullOrWhiteSpace($textValue)) {
            return $null
        }

        if ($textValue -eq 'true' -or $textValue -eq 'false') {
            return $textValue
        }

        return $null
    }

    function Join-QuotedValues {
        param([string[]]$Values)

        $filteredValues = Get-NonEmptyStrings -Values $Values
        if ($filteredValues.Count -eq 0) {
            return $null
        }

        return (@($filteredValues | Select-Object -Unique | ForEach-Object { '"' + $_ + '"' }) -join '; ')
    }

    $auditOnlyText = [string]$policyRoot.AuditOnly
    if ($auditOnlyText -eq 'true' -or $auditOnlyText -eq 'false') {
        Add-SummaryLine -Text ("AuditOnly: {0}" -f $auditOnlyText)
    }

    $minimumKeyLength = [string]$policyRoot.MinimumKeyLength
    $maximumKeyLength = [string]$policyRoot.MaximumKeyLength
    if (-not [string]::IsNullOrWhiteSpace($minimumKeyLength) -or -not [string]::IsNullOrWhiteSpace($maximumKeyLength)) {
        if (-not [string]::IsNullOrWhiteSpace($minimumKeyLength) -and -not [string]::IsNullOrWhiteSpace($maximumKeyLength)) {
            Add-SummaryLine -Text ("KeyLength Restricted to: min {0}, max {1}" -f $minimumKeyLength, $maximumKeyLength)
        }
        elseif (-not [string]::IsNullOrWhiteSpace($minimumKeyLength)) {
            Add-SummaryLine -Text ("KeyLength Restricted to: minimum {0}" -f $minimumKeyLength)
        }
        else {
            Add-SummaryLine -Text ("KeyLength Restricted to: maximum {0}" -f $maximumKeyLength)
        }
    }

    foreach ($directive in @(
            @{ Name = 'ReadSubjectFromRequest'; Label = 'SubjectSource'; Description = 'Read from original request' }
            @{ Name = 'SupplementDnsNames'; Label = 'SupplementDnsNames'; Description = 'Supplement DNS names from request' }
            @{ Name = 'SupplementUnqualifiedNames'; Label = 'SupplementUnqualifiedNames'; Description = 'Include unqualified names' }
        )) {
        $valueText = Convert-ToNullableBooleanText -Value $policyRoot.($directive.Name)
        if ($null -ne $valueText) {
            Add-SummaryLine -Text ("{0} Set to: {1} ({2})" -f $directive.Label, $valueText, $directive.Description)
        }
    }

    $notAfter = [string]$policyRoot.NotAfter
    if (-not [string]::IsNullOrWhiteSpace($notAfter)) {
        Add-SummaryLine -Text ('NotAfter Restricted to: "{0}"' -f $notAfter)
    }

    foreach ($permitEmptyDirectiveName in @('PermitEmptyIdentites', 'PermitEmptyIdentities')) {
        $permitEmptyValue = Convert-ToNullableBooleanText -Value $policyRoot.$permitEmptyDirectiveName
        if ($null -ne $permitEmptyValue) {
            if ($permitEmptyValue -eq 'true') {
                Add-SummaryLine -Text 'EmptyIdentities Allowed: true'
            }
            else {
                Add-SummaryLine -Text 'EmptyIdentities Forbidden: true'
            }

            break
        }
    }

    $securityIdentifierExtension = [string]$policyRoot.SecurityIdentifierExtension
    if (-not [string]::IsNullOrWhiteSpace($securityIdentifierExtension)) {
        switch ($securityIdentifierExtension) {
            'Deny' {
                Add-SummaryLine -Text 'SecurityIdentifierExtension Forbidden: incoming SID extension is denied'
            }
            'Remove' {
                Add-SummaryLine -Text 'SecurityIdentifierExtension Forbidden: incoming SID extension is removed'
            }
            'Allow' {
                Add-SummaryLine -Text 'SecurityIdentifierExtension Restricted to: Allow requested SID extension'
            }
            'Add' {
                Add-SummaryLine -Text 'SecurityIdentifierExtension Restricted to: Add SID extension from mapped AD object'
            }
            default {
                Add-SummaryLine -Text ("SecurityIdentifierExtension Set to: {0}" -f $securityIdentifierExtension)
            }
        }
    }

    foreach ($directiveList in @(
            @{ Name = 'AllowedCryptoProviders'; Label = 'CryptoProvider Restricted to' }
            @{ Name = 'DisallowedCryptoProviders'; Label = 'CryptoProvider Forbidden' }
            @{ Name = 'AllowedProcesses'; Label = 'Process Restricted to' }
            @{ Name = 'DisallowedProcesses'; Label = 'Process Forbidden' }
            @{ Name = 'CrlDistributionPoints'; Label = 'CRL Distribution Point URI Set to' }
            @{ Name = 'AuthorityInformationAccess'; Label = 'Authority Information Access URI Set to' }
            @{ Name = 'OnlineCertificateStatusProtocol'; Label = 'OCSP URI Set to' }
        )) {
        $joinedValues = Join-QuotedValues -Values @($policyRoot.($directiveList.Name).string)
        if (-not [string]::IsNullOrWhiteSpace($joinedValues)) {
            Add-SummaryLine -Text ("{0}: {1}" -f $directiveList.Label, $joinedValues)
        }
    }

    $subjectRuleMap = @{}
    foreach ($section in @('Subject', 'SubjectAlternativeName')) {
        $sectionNode = $policyRoot.$section
        if (-not $sectionNode) {
            continue
        }

        foreach ($rule in @($sectionNode.SubjectRule)) {
            if (-not $rule) {
                continue
            }

            $fieldName = [string]$rule.Field
            if ([string]::IsNullOrWhiteSpace($fieldName)) {
                continue
            }

            if (-not $subjectRuleMap.ContainsKey($fieldName)) {
                $subjectRuleMap[$fieldName] = [ordered]@{
                    AllowedPatterns      = New-Object System.Collections.Generic.List[string]
                    DeniedPatterns       = New-Object System.Collections.Generic.List[string]
                    MandatoryValues      = New-Object System.Collections.Generic.List[string]
                    MaxOccurrencesValues = New-Object System.Collections.Generic.List[string]
                    MinLengthValues      = New-Object System.Collections.Generic.List[string]
                    MaxLengthValues      = New-Object System.Collections.Generic.List[string]
                }
            }

            $mandatoryText = Convert-ToNullableBooleanText -Value $rule.Mandatory
            if ($null -ne $mandatoryText) {
                $subjectRuleMap[$fieldName].MandatoryValues.Add($mandatoryText)
            }

            $maxOccurrences = [string]$rule.MaxOccurrences
            if (-not [string]::IsNullOrWhiteSpace($maxOccurrences)) {
                $subjectRuleMap[$fieldName].MaxOccurrencesValues.Add($maxOccurrences)
            }

            $minLength = [string]$rule.MinLength
            if (-not [string]::IsNullOrWhiteSpace($minLength)) {
                $subjectRuleMap[$fieldName].MinLengthValues.Add($minLength)
            }

            $maxLength = [string]$rule.MaxLength
            if (-not [string]::IsNullOrWhiteSpace($maxLength)) {
                $subjectRuleMap[$fieldName].MaxLengthValues.Add($maxLength)
            }

            foreach ($patternNode in @($rule.Patterns.Pattern)) {
                $expression = [string]$patternNode.Expression
                if ([string]::IsNullOrWhiteSpace($expression)) {
                    continue
                }

                $treatAs = [string]$patternNode.TreatAs
                $decoratedExpression = if ([string]::IsNullOrWhiteSpace($treatAs)) {
                    $expression
                }
                else {
                    "{0} [TreatAs={1}]" -f $expression, $treatAs
                }

                if ([string]$patternNode.Action -eq 'Deny') {
                    $subjectRuleMap[$fieldName].DeniedPatterns.Add($decoratedExpression)
                }
                else {
                    $subjectRuleMap[$fieldName].AllowedPatterns.Add($decoratedExpression)
                }
            }
        }
    }

    foreach ($fieldName in @($subjectRuleMap.Keys | Sort-Object)) {
        $label = Convert-FieldLabel -Name $fieldName
        $fieldRule = $subjectRuleMap[$fieldName]

        $allowedPatternsJoined = Join-QuotedValues -Values @($fieldRule.AllowedPatterns)
        if (-not [string]::IsNullOrWhiteSpace($allowedPatternsJoined)) {
            Add-SummaryLine -Text ("{0} Restricted to: {1}" -f $label, $allowedPatternsJoined)
        }

        $deniedPatternsJoined = Join-QuotedValues -Values @($fieldRule.DeniedPatterns)
        if (-not [string]::IsNullOrWhiteSpace($deniedPatternsJoined)) {
            Add-SummaryLine -Text ("{0} Forbidden: {1}" -f $label, $deniedPatternsJoined)
        }

        $mandatoryValues = @($fieldRule.MandatoryValues | Select-Object -Unique)
        if ($mandatoryValues -contains 'true') {
            Add-SummaryLine -Text ("{0} Required: true" -f $label)
        }
        elseif ($mandatoryValues -contains 'false') {
            Add-SummaryLine -Text ("{0} Required: false" -f $label)
        }

        $maxOccurrenceValues = @($fieldRule.MaxOccurrencesValues | Select-Object -Unique)
        if ($maxOccurrenceValues.Count -gt 0) {
            Add-SummaryLine -Text ("{0} Occurrences Restricted to: {1}" -f $label, ($maxOccurrenceValues -join ', '))
        }

        $minLengthValues = @($fieldRule.MinLengthValues | Select-Object -Unique)
        if ($minLengthValues.Count -gt 0) {
            Add-SummaryLine -Text ("{0} Length Restricted to minimum: {1}" -f $label, ($minLengthValues -join ', '))
        }

        $maxLengthValues = @($fieldRule.MaxLengthValues | Select-Object -Unique)
        if ($maxLengthValues.Count -gt 0) {
            Add-SummaryLine -Text ("{0} Length Restricted to maximum: {1}" -f $label, ($maxLengthValues -join ', '))
        }
    }

    $directoryServicesMapping = $policyRoot.DirectoryServicesMapping
    if ($directoryServicesMapping) {
        $directoryAction = [string]$directoryServicesMapping.Action
        if (-not [string]::IsNullOrWhiteSpace($directoryAction)) {
            switch ($directoryAction) {
                'Deny' { Add-SummaryLine -Text 'DirectoryServicesMapping Forbidden: request is denied when mapping condition matches' }
                'Allow' { Add-SummaryLine -Text 'DirectoryServicesMapping Restricted to: mapped object must be found' }
                default { Add-SummaryLine -Text ("DirectoryServicesMapping Action Set to: {0}" -f $directoryAction) }
            }
        }

        $certificateAttribute = [string]$directoryServicesMapping.CertificateAttribute
        if (-not [string]::IsNullOrWhiteSpace($certificateAttribute)) {
            Add-SummaryLine -Text ('DirectoryServicesMapping CertificateAttribute Restricted to: "{0}"' -f $certificateAttribute)
        }

        $directoryServicesAttribute = [string]$directoryServicesMapping.DirectoryServicesAttribute
        if (-not [string]::IsNullOrWhiteSpace($directoryServicesAttribute)) {
            Add-SummaryLine -Text ('DirectoryServicesMapping DirectoryServicesAttribute Restricted to: "{0}"' -f $directoryServicesAttribute)
        }

        $objectCategory = [string]$directoryServicesMapping.ObjectCategory
        if (-not [string]::IsNullOrWhiteSpace($objectCategory)) {
            Add-SummaryLine -Text ('DirectoryServicesMapping ObjectCategory Restricted to: "{0}"' -f $objectCategory)
        }

        $searchRoot = [string]$directoryServicesMapping.SearchRoot
        if (-not [string]::IsNullOrWhiteSpace($searchRoot)) {
            Add-SummaryLine -Text ('SearchRoot restricted to OU: "{0}"' -f $searchRoot)
        }

        $allowedSecurityGroups = Get-NonEmptyStrings -Values @($directoryServicesMapping.AllowedSecurityGroups.string)
        if ($allowedSecurityGroups.Count -gt 0) {
            $quotedAllowedGroups = @($allowedSecurityGroups | Select-Object -Unique | ForEach-Object { '"' + $_ + '"' })
            Add-SummaryLine -Text ("AllowedSecurityGroup: {0}" -f ($quotedAllowedGroups -join '; '))
        }

        $disallowedSecurityGroups = Get-NonEmptyStrings -Values @($directoryServicesMapping.DisallowedSecurityGroups.string)
        if ($disallowedSecurityGroups.Count -gt 0) {
            $quotedDisallowedGroups = @($disallowedSecurityGroups | Select-Object -Unique | ForEach-Object { '"' + $_ + '"' })
            Add-SummaryLine -Text ("DisallowedSecurityGroup: {0}" -f ($quotedDisallowedGroups -join '; '))
        }

        $allowedOrganizationalUnits = Get-NonEmptyStrings -Values @($directoryServicesMapping.AllowedOrganizationalUnits.string)
        if ($allowedOrganizationalUnits.Count -gt 0) {
            $quotedAllowedOrganizationalUnits = @($allowedOrganizationalUnits | Select-Object -Unique | ForEach-Object { '"' + $_ + '"' })
            Add-SummaryLine -Text ("AllowedOrganizationalUnit: {0}" -f ($quotedAllowedOrganizationalUnits -join '; '))
        }

        $disallowedOrganizationalUnits = Get-NonEmptyStrings -Values @($directoryServicesMapping.DisallowedOrganizationalUnits.string)
        if ($disallowedOrganizationalUnits.Count -gt 0) {
            $quotedDisallowedOrganizationalUnits = @($disallowedOrganizationalUnits | Select-Object -Unique | ForEach-Object { '"' + $_ + '"' })
            Add-SummaryLine -Text ("DisallowedOrganizationalUnit: {0}" -f ($quotedDisallowedOrganizationalUnits -join '; '))
        }

        $customAttributes = Join-QuotedValues -Values @($directoryServicesMapping.CustomAttributes.string)
        if (-not [string]::IsNullOrWhiteSpace($customAttributes)) {
            Add-SummaryLine -Text ("DirectoryServicesMapping CustomAttribute Restricted to: {0}" -f $customAttributes)
        }

        $permitDisabledAccounts = Convert-ToNullableBooleanText -Value $directoryServicesMapping.PermitDisabledAccounts
        if ($null -ne $permitDisabledAccounts) {
            if ($permitDisabledAccounts -eq 'true') {
                Add-SummaryLine -Text 'DisabledAccount Allowed: true'
            }
            else {
                Add-SummaryLine -Text 'DisabledAccount Forbidden: true'
            }
        }

        $supplementServicePrincipalNames = Convert-ToNullableBooleanText -Value $directoryServicesMapping.SupplementServicePrincipalNames
        if ($null -ne $supplementServicePrincipalNames) {
            Add-SummaryLine -Text ("SupplementServicePrincipalNames Set to: {0}" -f $supplementServicePrincipalNames)
        }

        $addSidUniformResourceIdentifier = Convert-ToNullableBooleanText -Value $directoryServicesMapping.AddSidUniformResourceIdentifier
        if ($null -ne $addSidUniformResourceIdentifier) {
            Add-SummaryLine -Text ("AddSidUniformResourceIdentifier Set to: {0}" -f $addSidUniformResourceIdentifier)
        }

        $directoryObjectRuleMap = @{}
        foreach ($directoryObjectRule in @($directoryServicesMapping.DirectoryObjectRules.DirectoryObjectRule)) {
            if (-not $directoryObjectRule) {
                continue
            }

            $attributeName = [string]$directoryObjectRule.DirectoryServicesAttribute
            if ([string]::IsNullOrWhiteSpace($attributeName)) {
                continue
            }

            if (-not $directoryObjectRuleMap.ContainsKey($attributeName)) {
                $directoryObjectRuleMap[$attributeName] = [ordered]@{
                    AllowedPatterns = New-Object System.Collections.Generic.List[string]
                    DeniedPatterns  = New-Object System.Collections.Generic.List[string]
                    MandatoryValues = New-Object System.Collections.Generic.List[string]
                }
            }

            $mandatoryText = Convert-ToNullableBooleanText -Value $directoryObjectRule.Mandatory
            if ($null -ne $mandatoryText) {
                $directoryObjectRuleMap[$attributeName].MandatoryValues.Add($mandatoryText)
            }

            foreach ($patternNode in @($directoryObjectRule.Patterns.Pattern)) {
                $expression = [string]$patternNode.Expression
                if ([string]::IsNullOrWhiteSpace($expression)) {
                    continue
                }

                if ([string]$patternNode.Action -eq 'Deny') {
                    $directoryObjectRuleMap[$attributeName].DeniedPatterns.Add($expression)
                }
                else {
                    $directoryObjectRuleMap[$attributeName].AllowedPatterns.Add($expression)
                }
            }
        }

        foreach ($attributeName in @($directoryObjectRuleMap.Keys | Sort-Object)) {
            $ruleInfo = $directoryObjectRuleMap[$attributeName]

            $allowedPatternsJoined = Join-QuotedValues -Values @($ruleInfo.AllowedPatterns)
            if (-not [string]::IsNullOrWhiteSpace($allowedPatternsJoined)) {
                Add-SummaryLine -Text ("DirectoryObjectRule {0} Restricted to: {1}" -f $attributeName, $allowedPatternsJoined)
            }

            $deniedPatternsJoined = Join-QuotedValues -Values @($ruleInfo.DeniedPatterns)
            if (-not [string]::IsNullOrWhiteSpace($deniedPatternsJoined)) {
                Add-SummaryLine -Text ("DirectoryObjectRule {0} Forbidden: {1}" -f $attributeName, $deniedPatternsJoined)
            }

            $mandatoryValues = @($ruleInfo.MandatoryValues | Select-Object -Unique)
            if ($mandatoryValues -contains 'true') {
                Add-SummaryLine -Text ("DirectoryObjectRule {0} Required: true" -f $attributeName)
            }
            elseif ($mandatoryValues -contains 'false') {
                Add-SummaryLine -Text ("DirectoryObjectRule {0} Required: false" -f $attributeName)
            }
        }
    }

    foreach ($sectionName in @('OutboundSubject', 'OutboundSubjectAlternativeName')) {
        $setMap = @{}
        $removeList = New-Object System.Collections.Generic.List[string]

        foreach ($outboundRule in @($policyRoot.$sectionName.OutboundSubjectRule)) {
            if (-not $outboundRule) {
                continue
            }

            $fieldName = [string]$outboundRule.Field
            if ([string]::IsNullOrWhiteSpace($fieldName)) {
                continue
            }

            $fieldLabel = Convert-FieldLabel -Name $fieldName
            $value = [string]$outboundRule.Value

            if ([string]::IsNullOrWhiteSpace($value)) {
                $removeList.Add($fieldLabel)
                continue
            }

            if (-not $setMap.ContainsKey($fieldLabel)) {
                $setMap[$fieldLabel] = New-Object System.Collections.Generic.List[string]
            }

            $setMap[$fieldLabel].Add($value)
        }

        foreach ($fieldLabel in @($setMap.Keys | Sort-Object)) {
            $joinedValues = Join-QuotedValues -Values @($setMap[$fieldLabel])
            if (-not [string]::IsNullOrWhiteSpace($joinedValues)) {
                Add-SummaryLine -Text ("{0} {1} Set to: {2}" -f $sectionName, $fieldLabel, $joinedValues)
            }
        }

        $removeJoined = Join-QuotedValues -Values @($removeList)
        if (-not [string]::IsNullOrWhiteSpace($removeJoined)) {
            Add-SummaryLine -Text ("{0} Field Forbidden (removed): {1}" -f $sectionName, $removeJoined)
        }
    }

    $customExtensionEntries = New-Object System.Collections.Generic.List[string]
    foreach ($customCertificateExtension in @($policyRoot.CustomCertificateExtensions.CustomCertificateExtension)) {
        if (-not $customCertificateExtension) {
            continue
        }

        $oid = [string]$customCertificateExtension.Oid
        if ([string]::IsNullOrWhiteSpace($oid)) {
            continue
        }

        $value = [string]$customCertificateExtension.Value
        if ([string]::IsNullOrWhiteSpace($value)) {
            $customExtensionEntries.Add("OID={0}" -f $oid)
        }
        else {
            $customExtensionEntries.Add("OID={0}, Value={1}" -f $oid, $value)
        }
    }

    $customExtensionsJoined = Join-QuotedValues -Values @($customExtensionEntries)
    if (-not [string]::IsNullOrWhiteSpace($customExtensionsJoined)) {
        Add-SummaryLine -Text ("CustomCertificateExtension Set to: {0}" -f $customExtensionsJoined)
    }

    $yubiKeyPolicyEntries = New-Object System.Collections.Generic.List[string]
    foreach ($yubiKeyPolicy in @($policyRoot.YubiKeyPolicies.YubiKeyPolicy)) {
        if (-not $yubiKeyPolicy) {
            continue
        }

        $ruleParts = New-Object System.Collections.Generic.List[string]
        $action = [string]$yubiKeyPolicy.Action
        if (-not [string]::IsNullOrWhiteSpace($action)) {
            $ruleParts.Add("Action={0}" -f $action)
        }

        foreach ($propertyName in @('MinimumFirmwareVersion', 'MaximumFirmwareVersion')) {
            $propertyValue = [string]$yubiKeyPolicy.$propertyName
            if (-not [string]::IsNullOrWhiteSpace($propertyValue)) {
                $ruleParts.Add("{0}={1}" -f $propertyName, $propertyValue)
            }
        }

        foreach ($propertyName in @('PinPolicy', 'TouchPolicy', 'FormFactor', 'Edition', 'Slot', 'KeyAlgorithm')) {
            $listValues = Join-QuotedValues -Values @($yubiKeyPolicy.$propertyName.string)
            if (-not [string]::IsNullOrWhiteSpace($listValues)) {
                $ruleParts.Add("{0}={1}" -f $propertyName, $listValues)
            }
        }

        if ($ruleParts.Count -gt 0) {
            $yubiKeyPolicyEntries.Add(($ruleParts -join ', '))
        }
    }

    if ($yubiKeyPolicyEntries.Count -gt 0) {
        $yubiAllowEntries = New-Object System.Collections.Generic.List[string]
        $yubiDenyEntries = New-Object System.Collections.Generic.List[string]

        foreach ($entry in $yubiKeyPolicyEntries) {
            if ($entry -match 'Action=Deny') {
                $yubiDenyEntries.Add($entry)
            }
            else {
                $yubiAllowEntries.Add($entry)
            }
        }

        $yubiRestrictedJoined = Join-QuotedValues -Values @($yubiAllowEntries)
        if (-not [string]::IsNullOrWhiteSpace($yubiRestrictedJoined)) {
            Add-SummaryLine -Text ("YubiKeyPolicy Restricted to: {0}" -f $yubiRestrictedJoined)
        }

        $yubiForbiddenJoined = Join-QuotedValues -Values @($yubiDenyEntries)
        if (-not [string]::IsNullOrWhiteSpace($yubiForbiddenJoined)) {
            Add-SummaryLine -Text ("YubiKeyPolicy Forbidden: {0}" -f $yubiForbiddenJoined)
        }
    }

    if ($summaryLines.Count -eq 0) {
        $summaryLines.Add('TamemyCert XML is present but no readable hardening rules were found.')
    }

    $result.TamemyCertHardening = $true
    $result.TamemyCertHardeningSummary = $summaryLines -join "`n"
    return $result
}
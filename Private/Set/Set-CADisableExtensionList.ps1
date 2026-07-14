function Set-CADisableExtensionList {
    <#
    .SYNOPSIS
        Queries and stores the Disable Extension List configuration for each Certification Authority.

    .DESCRIPTION
        This function queries the DisableExtensionList registry value for each CA using PSCertutil's
        Get-PSCDisableExtensionList cmdlet. The DisableExtensionList indicates which certificate extensions
        are disabled on the CA, which is relevant for ESC16 detection (disabled CRL/AIA extensions).

        The function updates the AdcsObjectStore with:
        - DisableExtensionList: Array of disabled extension OIDs
        - SecurityExtensionDisabled: Boolean indicating if the security extension (1.3.6.1.4.1.311.25.2) is disabled

    .PARAMETER AdcsObject
        Pipeline input of LS2AdcsObject instances. Must contain DistinguishedName and CAFullName properties.

    .OUTPUTS
        PSCustomObject with DistinguishedName and CAFullName properties for pipeline continuation.

    .EXAMPLE
        Set-CAComputerPrincipal | Set-CAInterfaceFlags | Set-CAEditFlags | Set-CAAuditFilter | Set-CADisableExtensionList

    .NOTES
        Requires PSCertutil module with Get-PSCDisableExtensionList cmdlet.
        Part of the CA configuration pipeline in Invoke-Locksmith2.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [LS2AdcsObject[]]$AdcsObject
    )

    begin {
        Write-Verbose "Querying DisableExtensionList for Certification Authorities..."

        $canQueryDisableExtensionList = $true
        if (-not (Get-Command -Name Get-PSCDisableExtensionList -ErrorAction SilentlyContinue)) {
            $canQueryDisableExtensionList = $false
            Write-Warning "Get-PSCDisableExtensionList cmdlet not found. Continuing scan with default DisableExtensionList values."
        }

        function Set-DisableExtensionMetadata {
            param(
                [Parameter(Mandatory = $true)]
                [object]$Target,

                [Parameter()]
                [object[]]$DisableExtensionList,

                [Parameter()]
                [Nullable[bool]]$SecurityExtensionDisabled
            )

            if ($Target.PSObject.Properties['DisableExtensionList']) {
                $Target.DisableExtensionList = $DisableExtensionList
            }
            else {
                Add-Member -InputObject $Target -MemberType NoteProperty -Name 'DisableExtensionList' -Value $DisableExtensionList -Force
            }

            if ($Target.PSObject.Properties['SecurityExtensionDisabled']) {
                $Target.SecurityExtensionDisabled = $SecurityExtensionDisabled
            }
            else {
                Add-Member -InputObject $Target -MemberType NoteProperty -Name 'SecurityExtensionDisabled' -Value $SecurityExtensionDisabled -Force
            }
        }
    }

    process {
        $AdcsObject | Where-Object { $_.IsCertificationAuthority() } | ForEach-Object {
            try {
                $caName = $_.cn
                Write-Verbose "Processing CA: $caName"
                
                $dn = $_.distinguishedName

                $caFullName = $_.CAFullName
                if ([string]::IsNullOrEmpty($caFullName)) {
                    Write-Warning "CAFullName is empty for CA: $dn"
                    $_
                    return
                }

                Write-Verbose "  Querying DisableExtensionList for: $caFullName"

                if (-not $canQueryDisableExtensionList) {
                    Set-DisableExtensionMetadata -Target $_ -DisableExtensionList @() -SecurityExtensionDisabled $false
                    Write-Verbose "  PSCertutil cmdlet unavailable; applied defaults for DisableExtensionList"
                    $_
                    return
                }

                # Query DisableExtensionList using PSCertutil
                $disableExtensionListResult = Get-PSCDisableExtensionList -CAFullName $caFullName -ErrorAction Stop
                
                # Get-PSCDisableExtensionList returns an array of objects with DisabledExtension property
                # or $null if no extensions are disabled
                # Force array wrapping with @() for PS 5.1 compatibility (.Count on single objects)
                if ($disableExtensionListResult -and @($disableExtensionListResult).Count -gt 0) {
                    # Extract the extension OIDs/names into an array
                    $disabledExtensions = $disableExtensionListResult | ForEach-Object { $_.DisabledExtension }
                    Write-Verbose "  Retrieved $($disabledExtensions.Count) disabled extension(s): $($disabledExtensions -join ', ')"
                    
                    # Check if the Microsoft Certificate Template Information extension is disabled
                    # OID: 1.3.6.1.4.1.311.25.2 (szOID_CERTIFICATE_TEMPLATE)
                    $securityExtensionDisabled = $disabledExtensions -contains '1.3.6.1.4.1.311.25.2'
                    
                    if ($securityExtensionDisabled) {
                        Write-Verbose "  CRITICAL: Security extension (1.3.6.1.4.1.311.25.2) is DISABLED"
                    }
                    else {
                        Write-Verbose "  Security extension (1.3.6.1.4.1.311.25.2) is enabled"
                    }
                    
                    # Set properties directly on the LS2AdcsObject (same reference as store)
                    Set-DisableExtensionMetadata -Target $_ -DisableExtensionList $disabledExtensions -SecurityExtensionDisabled $securityExtensionDisabled
                    Write-Verbose "  Updated $($_.distinguishedName) with DisableExtensionList and SecurityExtensionDisabled"
                }
                else {
                    # No extensions disabled - set directly
                    Write-Verbose "  No extensions disabled on this CA"
                    Set-DisableExtensionMetadata -Target $_ -DisableExtensionList @() -SecurityExtensionDisabled $false
                    Write-Verbose "  Updated $($_.distinguishedName) with empty DisableExtensionList"
                }
            }
            catch {
                Write-Verbose "  Failed to query DisableExtensionList for '$caFullName': $($_.Exception.Message)"
                
                # Set to null on error
                Set-DisableExtensionMetadata -Target $_ -DisableExtensionList $null -SecurityExtensionDisabled $null
            }
            
            # Always return the object to continue the pipeline
            $_
        }
    }

    end {
        Write-Verbose "Completed DisableExtensionList queries for all CAs"
    }
}

function Show-IssueReport {
    <#
        .SYNOPSIS
        Displays discovered AD CS issues in console based on specified mode.

        .DESCRIPTION
        Formats and displays LS2Issue objects in the console using different output modes.
        Issues are grouped by technique with styled headers matching the original Locksmith format.
        
        Mode 0: Table format showing Name and Issue columns
        Mode 1: List format showing Name, Issue, Fix, and Revert properties

        .PARAMETER Issues
        Array of LS2Issue objects to display.

        .PARAMETER Mode
        Output mode for displaying issues:
        - 0: Table format (issues only)
        - 1: List format (issues with fix scripts)

        .INPUTS
        None. This function does not accept pipeline input.

        .OUTPUTS
        None. Outputs directly to console using Write-Host and Format-* cmdlets.

        .EXAMPLE
        $issues = Get-FlattenedIssues
        Show-IssueReport -Issues $issues -Mode 0
        
        Displays issues in table format.

        .EXAMPLE
        Show-IssueReport -Issues $issues -Mode 1
        
        Displays issues in list format with fix scripts.

        .NOTES
        Author: Jake Hildreth (@jakehildreth)
        Module: Locksmith2
        Requires: PowerShell 5.1+
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [LS2Issue[]]$Issues,

        [Parameter(Mandatory)]
        [ValidateSet(0, 1)]
        [int]$Mode
    )

    #requires -Version 5.1

    begin {
        Write-Verbose "Preparing issue report in Mode $Mode format..."
    }

    process {
        # Sort and group issues by technique
        $sortedIssues = $Issues | Sort-Object Technique, Name, Issue
        $issuesByTechnique = $sortedIssues | Group-Object -Property Technique | Sort-Object Name
        $templateTechniques = @('ESC1', 'ESC2', 'ESC3c1', 'ESC3c2', 'ESC4a', 'ESC4o', 'ESC9', 'ESC13', 'ESC15', 'SchemaV1')

        function Format-TamemyCertHardeningValue {
            param(
                [Parameter(Mandatory)]
                [LS2Issue]$Issue
            )

            if ($Issue.TamemyCertHardening -eq $true) {
                return 'True'
            }

            if ($Issue.TamemyCertHardening -eq $false) {
                return 'False'
            }

            return 'N/A'
        }

        # Prints the magenta technique banner shared by both display modes.
        function Write-TechniqueHeader {
            param(
                [Parameter(Mandatory)]
                [string]$Title
            )

            Write-Host ""
            Write-Host "$('-' * ($Title.Length + 10))" -ForegroundColor Black -BackgroundColor Magenta -NoNewline; Write-Host
            Write-Host "     " -BackgroundColor Magenta -NoNewline
            Write-Host $Title -BackgroundColor Magenta -ForegroundColor Black -NoNewline
            Write-Host "     " -BackgroundColor Magenta -NoNewline; Write-Host
            Write-Host "$('-' * ($Title.Length + 10))" -ForegroundColor Black -BackgroundColor Magenta -NoNewline; Write-Host
            Write-Host ""
        }

        # Builds the display object for one issue. Shared by both modes so the
        # TamemyCert/Fix/Revert projection logic exists in exactly one place.
        function New-IssueDisplayObject {
            param(
                [Parameter(Mandatory)]
                [LS2Issue]$Issue,

                [Parameter(Mandatory)]
                [bool]$IsTemplateTechnique,

                [switch]$IncludeFixRevert
            )

            $properties = [ordered]@{ Name = $Issue.Name }

            if ($IsTemplateTechnique) {
                $properties.TamemyCertHardening = Format-TamemyCertHardeningValue -Issue $Issue
                $properties.TamemyCertHardeningXmlName = if ($Issue.TamemyCertHardening -eq $true) { $Issue.TamemyCertHardeningXmlName } else { $null }
                $properties.TamemyCertHardeningSummary = $Issue.TamemyCertHardeningSummary
            }

            $properties.Issue = $Issue.Issue

            if ($IncludeFixRevert) {
                $properties.Fix = if ($Issue.Fix) { $ExecutionContext.InvokeCommand.ExpandString($Issue.Fix) } else { $null }
                $properties.Revert = if ($Issue.Revert) { $ExecutionContext.InvokeCommand.ExpandString($Issue.Revert) } else { $null }
            }

            [PSCustomObject]$properties
        }

        # Display based on mode
        switch ($Mode) {
            0 {
                # Mode 0: Table format (issues only) grouped by technique
                Write-Host "`n[i] Locksmith discovered the following AD CS issues:`n" -ForegroundColor Cyan

                foreach ($group in $issuesByTechnique) {
                    Write-TechniqueHeader -Title "$($group.Name) Issues"
                    $isTemplateTechnique = $group.Name -in $templateTechniques
                    if ($isTemplateTechnique) {
                        $displayIssues = foreach ($issue in $group.Group) {
                            New-IssueDisplayObject -Issue $issue -IsTemplateTechnique $true
                        }
                        $displayIssues | Format-Table -Property Name, TamemyCertHardening, TamemyCertHardeningXmlName, TamemyCertHardeningSummary, Issue -Wrap
                    }
                    else {
                        $group.Group | Format-Table -Property Name, Issue -Wrap
                    }
                }
            }
            1 {
                # Mode 1: List format (issues with fix scripts) grouped by technique
                Write-Host "`n[i] Locksmith discovered the following AD CS issues:`n" -ForegroundColor Cyan

                foreach ($group in $issuesByTechnique) {
                    Write-TechniqueHeader -Title "$($group.Name) Issues"
                    $isTemplateTechnique = $group.Name -in $templateTechniques

                    $displayIssues = foreach ($issue in $group.Group) {
                        New-IssueDisplayObject -Issue $issue -IsTemplateTechnique $isTemplateTechnique -IncludeFixRevert
                    }

                    if ($isTemplateTechnique) {
                        $displayIssues | Format-List -Property Name, TamemyCertHardening, TamemyCertHardeningXmlName, TamemyCertHardeningSummary, Issue, Fix, Revert
                    }
                    else {
                        $displayIssues | Format-List -Property Name, Issue, Fix, Revert
                    }
                }
            }
        }
    }
}

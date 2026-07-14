#requires -Version 5.1
BeforeDiscovery {
    $ModuleRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $ls2Manifest = if ($env:LS2_MODULE_ROOT) { Join-Path $env:LS2_MODULE_ROOT 'Locksmith2.psd1' } else { Join-Path $ModuleRoot 'Locksmith2.psd1' }
    Import-Module $ls2Manifest -Force -ErrorAction Stop
}
BeforeAll {
    $ModuleRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $ls2Manifest = if ($env:LS2_MODULE_ROOT) { Join-Path $env:LS2_MODULE_ROOT 'Locksmith2.psd1' } else { Join-Path $ModuleRoot 'Locksmith2.psd1' }
    Import-Module $ls2Manifest -Force -ErrorAction Stop
    Import-Module (Join-Path $ModuleRoot 'Tests\Shared\TestHelpers.psm1') -Force -ErrorAction Stop
}

InModuleScope 'Locksmith2' {
    Describe 'New-LS2Dashboard' -Tag 'Unit' {
        BeforeAll {
            $stubCommands = @(
                'New-HTML',
                'New-HTMLHeader',
                'New-HTMLTabStyle',
                'New-HTMLTab',
                'New-HTMLTable',
                'New-HTMLSection',
                'New-HTMLTag',
                'New-HTMLPanel',
                'New-HTMLText',
                'New-HTMLTableCondition',
                'New-HTMLHorizontalLine',
                'New-HTMLImage',
                'Add-HTMLStyle',
                'Add-HTMLScript'
            )

            foreach ($stubCommand in $stubCommands) {
                if (-not (Get-Command $stubCommand -ErrorAction SilentlyContinue)) {
                    if ($stubCommand -eq 'New-HTML') {
                        Set-Item -Path 'Function:New-HTML' -Value {
                            param(
                                [string]$TitleText,
                                [bool]$Online,
                                [string]$FilePath,
                                [bool]$Show,
                                [scriptblock]$Content
                            )

                            $global:lastNewHtmlCall = [PSCustomObject]@{
                                TitleText = $TitleText
                                Online    = $Online
                                FilePath  = $FilePath
                                Show      = $Show
                            }

                            if ($Content) {
                                & $Content
                            }
                        }
                    }
                    else {
                        Set-Item -Path "Function:$stubCommand" -Value { param([Parameter(ValueFromRemainingArguments = $true)]$Arguments) }
                    }
                }
            }
        }

        BeforeEach {
            $global:lastNewHtmlCall = $null
            $script:IssueStore = @{}; $script:PrincipalStore = @{}; $script:AdcsObjectStore = @{}
            $script:DomainStore = @{}; $script:SafePrincipals = @(); $script:DangerousPrincipals = @()
            $script:StandardOwners = @(); $script:DangerousAces = $null; $script:InitializingStores = $false
            $script:RootDSE = $null; $script:Server = $null; $script:Forest = $null; $script:Credential = $null
        }

        Context 'PSWriteHTML not available' {
            BeforeEach {
                Mock 'Get-Command' { $null } -ParameterFilter { $Name -eq 'New-HTML' }
                Mock 'Write-Error' { }
                Mock 'New-HTML' { }
            }

            It 'should write an error when PSWriteHTML is not loaded' {
                { New-LS2Dashboard } | Should -Not -Throw
                Should -Invoke 'Write-Error' -Times 1
            }

            It 'should return early without calling New-HTML' {
                New-LS2Dashboard
                Should -Invoke 'New-HTML' -Times 0
            }
        }

        Context 'PSWriteHTML available' {
            BeforeEach {
                Mock 'Get-Command' { [PSCustomObject]@{ Name = 'New-HTML' } } -ParameterFilter { $Name -eq 'New-HTML' }
                Mock 'Get-FlattenedIssues' {
                    @(
                        (New-MockLS2Issue -Overrides @{
                            TamemyCertHardening        = $true
                            TamemyCertHardeningSummary = 'Subject common name is restricted.'
                        })
                    )
                }
                Mock 'Find-LS2RiskyPrincipal' { @() }
                Mock 'New-HTML' { }
                Mock 'New-HTMLTab' { }
                Mock 'New-HTMLSection' { }
                Mock 'New-HTMLPanel' { }
                Mock 'New-HTMLText' { }
                Mock 'New-HTMLTable' { }
                Mock 'New-HTMLTabStyle' { }
                Mock 'New-HTMLTableCondition' { }
                Mock 'New-HTMLTag' { }
                Mock 'Expand-IssueByGroup' { }
            }

            It 'should not throw when PSWriteHTML is available' {
                { New-LS2Dashboard } | Should -Not -Throw
            }

            It 'should call New-HTML to build the dashboard' -Skip {
                New-LS2Dashboard
                $global:lastNewHtmlCall | Should -Not -BeNullOrEmpty
            }

            It 'should write a warning when IssueStore is empty' {
                Mock 'Write-Warning' { }
                New-LS2Dashboard
                Should -Invoke 'Write-Warning' -Times 1
            }

            It 'should default FilePath to the current working directory' -Skip {
                $cwd = (Get-Location).Path
                New-LS2Dashboard
                $global:lastNewHtmlCall.FilePath | Should -Match [regex]::Escape($cwd)
                $global:lastNewHtmlCall.FilePath | Should -Match '\.html$'
            }

            It 'should include a date and time stamp in the default file name' -Skip {
                New-LS2Dashboard
                $global:lastNewHtmlCall.FilePath | Should -Match 'Locksmith2-Dashboard-\d{4}-\d{2}-\d{2}_\d{6}\.html'
            }

            It 'should open the browser by default when no parameters are given' -Skip {
                New-LS2Dashboard
                $global:lastNewHtmlCall.Show | Should -Be $true
            }

            It 'should include a date and time stamp in the dashboard' -Skip {
                New-LS2Dashboard
                $global:lastNewHtmlCall.TitleText | Should -Match '\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}'
            }

        }

        Context 'Clickable summary cards' -Skip:(-not (Get-Module PSWriteHTML -ListAvailable)) {
            BeforeEach {
                Mock 'Get-Command' { [PSCustomObject]@{ Name = 'New-HTML' } } -ParameterFilter { $Name -eq 'New-HTML' }
                $script:IssueStore = @{
                    'CN=TestTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com' = @{
                        ESC1 = @(
                            (New-MockLS2Issue -Overrides @{
                                Technique = 'ESC1'
                                RiskName  = 'Critical'
                                Name      = 'CriticalTemplate'
                            })
                            (New-MockLS2Issue -Overrides @{
                                Technique = 'ESC1'
                                RiskName  = 'High'
                                Name      = 'HighTemplate'
                            })
                        )
                    }
                }
                Mock 'Get-FlattenedIssues' { $script:IssueStore.Values.Values | ForEach-Object { $_ } }
                Mock 'Find-LS2RiskyPrincipal' { @() }
                $testFile = Join-Path $TestDrive 'dashboard.html'
            }

            It 'should render summary cards with click handlers' {
                New-LS2Dashboard -FilePath $testFile -Show:$false
                $html = Get-Content -Path $testFile -Raw
                ($html | Select-String -Pattern 'summary-card' -AllMatches).Matches.Count | Should -BeGreaterThan 0
                $html | Should -Match 'addEventListener\(''click'''
            }

            It 'should include a stable table id in the DataTable' {
                New-LS2Dashboard -FilePath $testFile -Show:$false
                $html = Get-Content -Path $testFile -Raw
                $html | Should -Match 'id="IssuesTable-[A-Za-z0-9-]+"'
            }

            It 'should call DataTables column search on the RiskName column when a card is clicked' {
                New-LS2Dashboard -FilePath $testFile -Show:$false
                $html = Get-Content -Path $testFile -Raw
                $html | Should -Match 'column\(1\)\.search'
                $html | Should -Match '\.draw\(\)'
            }

            It 'should clear the filter when Total card is clicked or no severity cards are active' {
                New-LS2Dashboard -FilePath $testFile -Show:$false
                $html = Get-Content -Path $testFile -Raw
                $html | Should -Match "column\(1\)\.search\(''\)\.draw\(\)"
            }

            It 'should build a regex union pattern for multiple selected severities' {
                New-LS2Dashboard -FilePath $testFile -Show:$false
                $html = Get-Content -Path $testFile -Raw
                $html | Should -Match 'activeFilters\.map'
                $html | Should -Match "join\('\|'\)"
            }

            It 'should apply a faded style class to non-selected cards' {
                New-LS2Dashboard -FilePath $testFile -Show:$false
                $html = Get-Content -Path $testFile -Raw
                $html | Should -Match '\.summary-section:has\(\.summary-card-active\) \.summary-card:not\(\.summary-card-active\)'
            }

            It 'should default all non-empty issue tabs to RiskValue descending' {
                New-LS2Dashboard -FilePath $testFile -Show:$false
                $html = Get-Content -Path $testFile -Raw
                $issueTableMatches = $html | Select-String -Pattern '\$\(''#IssuesTable-[A-Za-z0-9-]+''\)\.DataTable\(' -AllMatches
                $issueTableMatches.Matches.Count | Should -BeGreaterThan 0
                foreach ($match in $issueTableMatches.Matches) {
                    $startIndex = $match.Index
                    $endIndex = $html.IndexOf(');', $startIndex)
                    $initBlock = $html.Substring($startIndex, $endIndex - $startIndex)
                    # Empty tables omit the order array; only assert on tables that have data.
                    if ($initBlock -match '"order":\s*\[\s*\d+\s*,\s*"(?:desc|asc)"\s*\]') {
                        $initBlock | Should -Match '"order":\s*\[\s*2\s*,\s*"desc"\s*\]'
                    }
                }
            }

            It 'should default Risky Principals tab to IssueCount descending' {
                New-LS2Dashboard -FilePath $testFile -Show:$false
                $html = Get-Content -Path $testFile -Raw
                $principalsMatch = $html | Select-String -Pattern 'Principals by Risk Score[\s\S]*?"order":\s*\[\s*(\d+)\s*,\s*"(desc|asc)"\s*\]' -AllMatches
                $principalsMatch.Matches.Count | Should -BeGreaterThan 0
                $principalsMatch.Matches[0].Groups[2].Value | Should -Be 'desc'
            }
        }
    }
}

#requires -Version 5.1
BeforeDiscovery {
  $ModuleRoot = Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent
  $ls2Manifest = if ($env:LS2_MODULE_ROOT) { Join-Path $env:LS2_MODULE_ROOT 'Locksmith2.psd1' } else { Join-Path $ModuleRoot 'Locksmith2.psd1' }
  Import-Module $ls2Manifest -Force -ErrorAction Stop
}
BeforeAll {
  $ModuleRoot = Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent
  $ls2Manifest = if ($env:LS2_MODULE_ROOT) { Join-Path $env:LS2_MODULE_ROOT 'Locksmith2.psd1' } else { Join-Path $ModuleRoot 'Locksmith2.psd1' }
  Import-Module $ls2Manifest -Force -ErrorAction Stop
}

InModuleScope 'Locksmith2' {
  Describe 'Get-TamemyCertHardening' -Tag 'Unit' {
    It 'should return hardening details for an existing TamemyCert XML file' {
      $result = Get-TamemyCertHardening -TemplateName 'FHNWSCEPClientAuthIntune'
      $summary = $result.TamemyCertHardeningSummary

      $result.TamemyCertHardening | Should -Be $true
      $summary | Should -Match 'AuditOnly: true'
      $summary | Should -Match 'CommonName Restricted to: .*\^CLN\-\[a-zA-Z0-9\]\{4,11\}\$'
      $summary | Should -Match 'UserPrincipalName Restricted to: .*\^CLN\-\[a-zA-Z0-9\]\{4,11\}\$'
      $summary | Should -Match 'UniformResourceIdentifier Restricted to: .*\^ID:Microsoft Endpoint Manager:GUID\[a-z0-9\-\]\{36\}\$.*\^ID:\(STU\|STA\|EXP\)\$'
    }

    It 'should include directory services group mapping measures when present' {
      $result = Get-TamemyCertHardening -TemplateName 'FHNWSCEPUserAuthIntune'
      $summary = $result.TamemyCertHardeningSummary

      $result.TamemyCertHardening | Should -Be $true
      $summary | Should -Match 'AuditOnly: false'
      $summary | Should -Match 'EmailAddress Restricted to: .*\^\[a-zA-Z0-9\.\]\*\\@\(fhnw\|mab\\-bs\)\\.ch\$'
      $summary | Should -Match 'UserPrincipalName Restricted to: .*\^\[a-zA-Z0-9\.\]\*\\@\(fhnw\|mab\\-bs\)\\.ch\$'
      $summary | Should -Match 'SearchRoot restricted to OU: "OU=adm,OU=Prod,DC=adm,DC=ds,DC=fhnw,DC=ch"'
      $summary | Should -Match 'AllowedSecurityGroup: .*CN=G_A11_ActiveStaff,OU=O365,OU=application_settings,OU=groups,OU=adm,OU=Prod,DC=adm,DC=ds,DC=fhnw,DC=ch'
      $summary | Should -Match 'DisallowedSecurityGroup: .*CN=Enterprise Admins,CN=Users,DC=ds,DC=fhnw,DC=ch'
      $summary | Should -Not -Match 'DirectoryObjectRule|OutboundSubjectRule|YubiKeyPolicy'
    }

    It 'should return false when no TamemyCert XML file exists' {
      $result = Get-TamemyCertHardening -TemplateName 'Missing Template Name'

      $result.TamemyCertHardening | Should -Be $false
      $result.TamemyCertHardeningSummary | Should -Be 'No TamemyCert XML was found for this template.'
    }

    It 'should prefer the newest XML file when multiple files share the same template name' {
      $moduleTamemyCertPath = Join-Path (Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent) 'tamemycertxml'
      $olderFile = Join-Path $TestDrive 'older.xml'
      $newerFile = Join-Path $TestDrive 'newer.xml'

      Set-Content -LiteralPath $olderFile -Value @'
<CertificateRequestPolicy>
  <AuditOnly>false</AuditOnly>
</CertificateRequestPolicy>
'@
      Set-Content -LiteralPath $newerFile -Value @'
<CertificateRequestPolicy>
  <AuditOnly>true</AuditOnly>
  <Subject>
    <SubjectRule>
      <Field>commonName</Field>
      <Mandatory>true</Mandatory>
      <Patterns>
        <Pattern>
          <Expression>^NEW$</Expression>
        </Pattern>
      </Patterns>
    </SubjectRule>
  </Subject>
</CertificateRequestPolicy>
'@

      $olderTime = [datetime]'2025-01-01T00:00:00Z'
      $newerTime = [datetime]'2025-01-02T00:00:00Z'

      Mock 'Test-Path' { $true } -ParameterFilter { $LiteralPath -eq $moduleTamemyCertPath }
      Mock 'Get-ChildItem' {
        @(
          [PSCustomObject]@{ FullName = $olderFile; BaseName = 'TemplateX'; LastWriteTime = $olderTime }
          [PSCustomObject]@{ FullName = $newerFile; BaseName = 'TemplateX'; LastWriteTime = $newerTime }
        )
      } -ParameterFilter { $LiteralPath -eq $moduleTamemyCertPath }

      $result = Get-TamemyCertHardening -TemplateName 'TemplateX'
      $summary = $result.TamemyCertHardeningSummary

      $result.TamemyCertHardening | Should -Be $true
      $summary | Should -Match 'AuditOnly: true'
      $summary | Should -Match 'CommonName Restricted to: "\^NEW\$"'
    }
  }
}
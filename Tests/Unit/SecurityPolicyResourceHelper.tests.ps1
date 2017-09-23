
#region HEADER

# Unit Test Template Version: 1.2.0
$script:moduleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if ( (-not (Test-Path -Path (Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests'))) -or `
     (-not (Test-Path -Path (Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests\TestHelper.psm1'))) )
{
    & git @('clone','https://github.com/PowerShell/DscResource.Tests.git',(Join-Path -Path $script:moduleRoot -ChildPath '\DSCResource.Tests\'))
}

Import-Module -Name (Join-Path -Path $script:moduleRoot -ChildPath (Join-Path -Path 'DSCResource.Tests' -ChildPath 'TestHelper.psm1')) -Force

$TestEnvironment = Initialize-TestEnvironment `
    -DSCModuleName 'SecurityPolicyDsc' `
    -DSCResourceName 'SecurityPolicyResourceHelper' `
    -TestType Unit

#endregion HEADER

# Begin Testing
try
{
    InModuleScope 'SecurityPolicyResourceHelper' {
        Describe 'Test helper functions' {
            
            Context 'Test ConvertTo-LocalFriendlyName' {
                $sid = 'S-1-5-32-544'
                It 'Should be BUILTIN\Administrators' {
                    ConvertTo-LocalFriendlyName -Identity $sid | should be 'BUILTIN\Administrators'
                }

                It "Should return $env:USERDOMAIN\administrator" {   
                    ConvertTo-LocalFriendlyName -Identity 'administrator' | Should be "$env:USERDOMAIN\administrator"
                }
            }
            Context 'Test Invoke-Secedit' {
                Mock Start-Process -MockWith {} -ModuleName SecurityPolicyResourceHelper
                $invokeSeceditParameters = @{
                    InfPath = 'temp.inf'
                    SeceditOutput      = 'output.txt'
                    OverWrite          = $true
                }

                It 'Should not throw' {
                    {Invoke-Secedit @invokeSeceditParameters} | Should not throw
                }

                It 'Should call Start-Process' {
                    Assert-MockCalled -CommandName Start-Process -Exactly 1 -Scope Context -ModuleName SecurityPolicyResourceHelper
                }
            }
            Context 'Test Get-UserRightsAssignment' {
                $ini = "$PSScriptRoot..\..\..\Misc\TestHelpers\TestIni.txt"
                Mock -CommandName ConvertTo-LocalFriendlyName -MockWith {'Value1'}

                $result = Get-UserRightsAssignment $ini

                It 'Should match INI Section' {
                    $result.Keys | Should Be 'section'
                }
                
                It 'Should match INI Comment' {
                    $result.section.Comment1 | Should Be '; this is a comment'
                }

                It 'Should be Value1' {
                    $result.section.Key1 | Should be 'Value1'
                }
            }
            Context 'Test Test-IdentityIsNull' {
                
                It 'Should return true when Identity is null' {
                    $IdentityIsNull = Test-IdentityIsNull -Identity $null
                    $IdentityIsNull | Should Be $true
                }
                It 'Should return true when Identity is empty' {
                    $IdentityIsNull = Test-IdentityIsNull -Identity ''
                    $IdentityIsNull | Should Be $true
                }
                It 'Should return false when Identity is Guest' {
                    $IdentityIsNull = Test-IdentityIsNull -Identity 'Guest'
                    $IdentityIsNull | Should Be $false
                }
            }
            Context 'Get-SecurityPolicy' {
                $ini = "$PSScriptRoot..\..\..\Misc\TestHelpers\sample.inf"
                $iniPath = Get-Item -Path $ini
                Mock -CommandName Join-Path -MockWith {$iniPath.FullName}
                Mock -CommandName Remove-Item -MockWith {}
                $securityPolicy = Get-SecurityPolicy -Area 'USER_RIGHTS'

                It 'Should return Builtin\Administrators' {
                    $securityPolicy.SeLoadDriverPrivilege | Should Be 'BUILTIN\Administrators'
                }
            }
        } 
    }
}
finally
{
    Restore-TestEnvironment -TestEnvironment $TestEnvironment
}

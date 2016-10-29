<#
    .SYNOPSIS
        Template for creating DSC Resource Unit Tests
    .DESCRIPTION
        To Use:
        1. Copy to \Tests\Unit\ folder and rename <ResourceName>.tests.ps1 (e.g. MSFT_xFirewall.tests.ps1)
        2. Customize TODO sections.
        3. Delete all template comments (TODOs, etc.)

    .NOTES
        There are multiple methods for writing unit tests. This template provides a few examples
        which you are welcome to follow but depending on your resource, you may want to
        design it differently. Read through our TestsGuidelines.md file for an intro on how to
        write unit tests for DSC resources: https://github.com/PowerShell/DscResources/blob/master/TestsGuidelines.md
#>

#region HEADER

# Unit Test Template Version: 1.2.0
$script:moduleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if ( (-not (Test-Path -Path (Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests'))) -or `
     (-not (Test-Path -Path (Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests\TestHelper.psm1'))) )
{
    & git @('clone','https://github.com/PowerShell/DscResource.Tests.git',(Join-Path -Path $script:moduleRoot -ChildPath '\DSCResource.Tests\'))
}

Import-Module (Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests\TestHelper.psm1') -Force

$TestEnvironment = Initialize-TestEnvironment `
    -DSCModuleName 'SecEditDSC' `
    -DSCResourceName 'MSFT_SecInf' `
    -TestType Unit 

#endregion HEADER

function Invoke-TestSetup {

}

function Replace-HashValue
{
    param
    (

        $HashTable,
        $Key,
        $NewValue
    )

    $HashTable.Remove($key)
    $HashTable.Add($Key,$NewValue)
    $HashTable
}

function Invoke-TestCleanup {
    Restore-TestEnvironment -TestEnvironment $TestEnvironment
    
}

# Begin Testing
try
{
    Invoke-TestSetup

    InModuleScope 'MSFT_SecInf' {
        
        Describe 'The system is not in a desired state' {
            $testParameters = @{
                PathToInf = 'C:\baseline.inf'
            }
            $mockResults = Import-Clixml -Path "$PSScriptRoot...\..\..\Misc\MockObjects\MockResults.xml"

            Context 'Get and Test method tests' {

                It 'Should return path of desired inf' {
                    $getResult = Get-TargetResource -PathToInf $testParameters.PathToInf
                    $getResult.PathToInf | Should be $testParameters.PathToInf
                }

                It 'Test method should return FALSE' {
                                      
                    Mock -CommandName Get-CurrentPolicy -MockWith {$mockResults}
                    Mock -CommandName Backup-SecurityPolicy -MockWith {}
                    Mock -CommandName Get-SecInfFile -MockWith {}
                    Mock -CommandName Test-Path -MockWith {$true}
                    Mock -CommandName Get-UserRightsAssignment -MockWith {}
                    Mock -CommandName Get-Module -MockWith {}

                    foreach($key in $mockResults.keys)
                    {
                        $modifiedMockResults = $mockResults.clone()
                        $mockFalseResults = Replace-HashValue -HashTable $modifiedMockResults -Key $key -NewValue NoIdentity
                 
                        Mock -CommandName Get-DesiredPolicy -MockWith {$mockFalseResults}
                        Test-TargetResource -PathToInf $testParameters.PathToInf | should be $false
                    }
                }
            }

            Context 'Set method tests' {
                    Mock Restore-SecurityPolicy  -MockWith {}
                    Mock Invoke-Secedit -MockWith {}
                    Mock Test-TargetResource -MockWith {$true}

                It 'Should call Invoke-Secedit when SecurityCmdlet module does not exist' {
                    
                    Mock Get-Module -MockWith {$false}                 

                    {Set-TargetResource -PathToInf $testParameters.PathToInf} | should not throw
                    Assert-MockCalled -CommandName Invoke-Secedit -Exactly 1
                }

                It 'Should Call Restore-SecurityPolicy when SecurityCmdlet module does exist' {
                    Mock Get-Module -MockWith {$true}
                    {Set-TargetResource -PathToInf $testParameters.PathToInf} | should not throw
                    Assert-MockCalled -CommandName Restore-SecurityPolicy -Exactly 1                    
                }
            }
        }

        Describe 'The system is in a desired state' {
            Context 'Test for Test emthod' {
                $mockResults = Import-Clixml -Path "$PSScriptRoot...\..\..\Misc\MockObjects\MockResults.xml"

                It 'Test method should return TRUE' {
                    Mock -CommandName Get-CurrentPolicy -MockWith {$mockResults}
                    Mock -CommandName Get-DesiredPolicy -MockWith {$mockResults}
                    Mock -CommandName Backup-SecurityPolicy -MockWith {}
                    Mock -CommandName Get-SecInfFile -MockWith {}
                    Mock -CommandName Test-Path -MockWith {$true}
                    Mock -CommandName Get-UserRightsAssignment -MockWith {}
                    Mock -CommandName Get-Module -MockWith {}
                    
                    Test-TargetResource -PathToInf 'C:\Security.inf' | should be $true
                       
                }
            }
        }        
    }
}
finally
{
    Invoke-TestCleanup
}

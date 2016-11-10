
#region HEADER

$script:moduleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if ( (-not (Test-Path -Path (Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests'))) -or `
     (-not (Test-Path -Path (Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests\TestHelper.psm1'))) )
{
    & git @('clone','https://github.com/PowerShell/DscResource.Tests.git',(Join-Path -Path $script:moduleRoot -ChildPath '\DSCResource.Tests\'))
}

Import-Module (Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests\TestHelper.psm1') -Force

$TestEnvironment = Initialize-TestEnvironment `
    -DSCModuleName 'SecurityPolicyDsc' `
    -DSCResourceName 'MSFT_SecInf' `
    -TestType Unit 

#endregion HEADER

function Set-HashValue
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
    InModuleScope 'MSFT_SecInf' {
        
        Describe 'The system is not in a desired state' {
            $testParameters = @{
                Path = 'C:\baseline.inf'
            }
            $mockResults = Import-Clixml -Path "$PSScriptRoot...\..\..\Misc\MockObjects\MockResults.xml"

            Context 'Get and Test method tests' {

                It 'Should return path of desired inf' {
                    $getResult = Get-TargetResource -Path $testParameters.Path
                    $getResult.Path | Should be $testParameters.Path
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
                        $mockFalseResults = Set-HashValue -HashTable $modifiedMockResults -Key $key -NewValue NoIdentity
                 
                        Mock -CommandName Get-DesiredPolicy -MockWith {$mockFalseResults}
                        Test-TargetResource -Path $testParameters.Path | should be $false
                    }
                }
            }

            Context 'Set method tests' {
                    Mock Restore-SecurityPolicy  -MockWith {}
                    Mock Invoke-Secedit -MockWith {}
                    Mock Test-TargetResource -MockWith {$true}

                It 'Should call Invoke-Secedit when SecurityCmdlet module does not exist' {
                    
                    Mock Get-Module -MockWith {$false}                 

                    {Set-TargetResource -Path $testParameters.Path} | should not throw
                    Assert-MockCalled -CommandName Invoke-Secedit -Exactly 1
                }

                It 'Should Call Restore-SecurityPolicy when SecurityCmdlet module does exist' {
                    Mock Get-Module -MockWith {$true}
                    {Set-TargetResource -Path $testParameters.Path} | should not throw
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
                    
                    Test-TargetResource -Path 'C:\Security.inf' | should be $true
                       
                }
            }
        }        
    }
}

finally
{
    Invoke-TestCleanup
}

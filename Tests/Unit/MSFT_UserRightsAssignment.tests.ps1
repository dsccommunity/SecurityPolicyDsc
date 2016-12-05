
$script:DSCModuleName    = 'SecurityPolicyDsc' 
$script:DSCResourceName  = 'MSFT_UserRightsAssignment'

#region HEADER
$script:moduleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if ( (-not (Test-Path -Path (Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests'))) -or `
     (-not (Test-Path -Path (Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests\TestHelper.psm1'))) )
{
    & git @('clone','https://github.com/PowerShell/DscResource.Tests.git',(Join-Path -Path $script:moduleRoot -ChildPath '\DSCResource.Tests\'))
}

Import-Module (Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests\TestHelper.psm1') -Force
$TestEnvironment = Initialize-TestEnvironment `
    -DSCModuleName $script:DSCModuleName `
    -DSCResourceName $script:DSCResourceName `
    -TestType Unit 
#endregion

# Begin Testing
try
{
    #region Pester Tests

    InModuleScope $script:DSCResourceName {

            $testUSR = [PSObject]@{
                Policy   = 'Access_Credential_Manager_as_a_trusted_caller'                
                Identity = 'contoso\TestUser1'                
            }

            $mockUSR = [PSObject]@{
                Policy = 'SeTrustedCredManAccessPrivilege'
                Identity = 'contoso\testUser1','contoso\TestUser2'
                PolicyFriendlyName = $testUSR.Policy
            }

            $mockGetTargetTesult = [PSObject] @{
                Policy = 'Access_Credential_Manager_as_a_trusted_caller'
                Identity = 'contoso\TestUser2'
            }
        #endregion

        #region Function Get-TargetResource
        Describe "Get-TargetResource" {        
               
            Context 'Identity should not match on Policy' {

                Mock Get-USRPolicy -MockWith {return @($mockUSR)}
                Mock Test-TargetResource -MockWith {$false}

                It 'Should return absent Identity' {                    
                    $Result = Get-TargetResource @testUSR

                    $Result.ActualIdentity | Should Not BeExactly $testUSR.Identity
                }

                It 'Should call expected Mocks' {
                    Assert-MockCalled -CommandName Get-USRPolicy -Exactly 1
                }
            }
        }
        #endregion

        #region Function Set-TargetResource
        Describe "Test-TargetResource" {
            Context 'Identity does exist' {

                Mock Get-USRPolicy -MockWith {$mockUSR}

                It 'Should return true' {
                    $testResult = Test-TargetResource @testUSR

                    $testResult | Should Be $true
                }

                It 'Should call expected mocks' {
                    Assert-MockCalled -CommandName Get-USRPolicy -Exactly 1
                }
            }

            Context 'Identity does not exist' {

                Mock Get-USRPolicy

                It 'Should return false' {
                    $testResult = Test-TargetResource @testUSR

                    $testResult | Should Be $false
                }

                It 'Should call expected mocks' {
                    Assert-MockCalled -CommandName Get-USRPolicy -Exactly 1
                } 
            }
        }
        #endregion
        #region Function Test-TargetResource
        Describe "Set-TargetResource" {

            Context 'Identity does not exist but should' {

                Mock Invoke-Secedit
                Mock Test-TargetResource -MockWith {$true}
                Mock Get-Content -ParameterFilter {$Path -match "Secedit-OutPut.txt"} -MockWith {"Tasked Failed"}             

                It 'Should not throw' {                    

                    {Set-TargetResource @testUSR} | Should Not Throw
                }

                It 'Should throw when set fails' {
                    Mock Test-TargetResource -MockWith {$false}  
                    {Set-TargetResource @testUSR} | Should Throw
 
                }
                It 'Should call expected mocks' {
                    Assert-MockCalled -CommandName Invoke-Secedit -Exactly 2
                    Assert-MockCalled -CommandName Test-TargetResource -Exactly 2
                }
            }
        }
        #endregion 
    }
    #endregion
}
finally
{
    #region FOOTER
    Restore-TestEnvironment -TestEnvironment $TestEnvironment
    #endregion
}

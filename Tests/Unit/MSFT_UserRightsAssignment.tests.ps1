<#
.Synopsis
   Template for creating DSC Resource Unit Tests
.DESCRIPTION
   To Use:
     1. Copy to \Tests\Unit\ folder and rename MSFT_x<ResourceName>.tests.ps1
     2. Customize TODO sections.

.NOTES
   Code in HEADER and FOOTER regions are standard and may be moved into DSCResource.Tools in
   Future and therefore should not be altered if possible.
#>


# TODO: Customize these parameters...
$Global:DSCModuleName      = 'xSecedit' # Example xNetworking
$Global:DSCResourceName    = 'MSFT_xUserRightsAssignment' # Example MSFT_xFirewall
# /TODO

#region HEADER
if ( (-not (Test-Path -Path '.\DSCResource.Tests\')) -or `
     (-not (Test-Path -Path '.\DSCResource.Tests\TestHelper.psm1')) )
{
    & git @('clone','https://github.com/PowerShell/DscResource.Tests.git')
}
else
{
    & git @('-C',(Join-Path -Path (Get-Location) -ChildPath '\DSCResource.Tests\'),'pull')
}
Import-Module .\DSCResource.Tests\TestHelper.psm1 -Force
$TestEnvironment = Initialize-TestEnvironment `
    -DSCModuleName $Global:DSCModuleName `
    -DSCResourceName $Global:DSCResourceName `
    -TestType Unit 
#endregion

# TODO: Other Optional Init Code Goes Here...
#Copy-Item -Path $PSScriptRoot\..\..\DSCResources\Library\Helper.psm1 -Destination TestDrive:\Helper.ps1 -Force

# Begin Testing
try
{

    #region Pester Tests

    # The InModuleScope command allows you to perform white-box unit testing on the internal
    # (non-exported) code of a Script Module.
    InModuleScope $Global:DSCResourceName {

        #region Pester Test Initialization
        # TODO: Optopnal Load Mock for use in Pester tests here...

            $testUSR = [PSObject]@{
                Policy         = 'Access_Credential_Manager_as_a_trusted_caller'                
                Identity       = 'contoso\TestUser1'
                Ensure         = 'Present'
            }

            $mockUSR = [PSObject]@{
                Policy = 'SeTrustedCredManAccessPrivilege'
                Identity = 'contoso\testUser1','contoso\TestUser2'
                PolicyFriendlyName = $testUSR.Policy

            }

            $mockGetTargetTesult = [PSObject] @{
                Policy = 'Access_Credential_Manager_as_a_trusted_caller'
		        Identity = 'contoso\TestUser2'
                Ensure = 'Present'
                ActualIdentity = 'contoso\TestUser1'
            }
        #endregion


        #region Function Get-TargetResource
        Describe "$($Global:DSCResourceName)\Get-TargetResource" {
        
               
            Context 'Identity is not present on Policy' {

                Mock Get-USRPolicy -MockWith {return @($mockUSR)}
                Mock Test-TargetResource -MockWith {$false}

                It 'Should return absent Identity' {
                    
                    $Result = Get-TargetResource @testUSR

                    $Result.Ensure | Should Be 'Absent'
                }

                It 'Should call expected Mocks' {
                    Assert-MockCalled -CommandName Get-USRPolicy -Exactly 1
                }
            }

            Context 'Identity does exist on Policy' {
           
                Mock Get-USRPolicy -MockWith {return @($mockUSR)}
                Mock Test-TargetResource -MockWith {return $true }

                It 'Should return Present' {

                    $Result = Get-TargetResource @testUSR

                    $Result.Ensure         | Should Be 'Present'
                    $Result.Policy         | Should Be $testUSR.Policy
                    $Result.Identity       | Should Be $testUSR.Identity
                    $Result.ActualIdnetity | Should Be $testUSR.ActualIdnetity
                }

                It 'Should call the expected mocks' {

                    Assert-MockCalled -CommandName Get-USRPolicy -Exactly 1
                    Assert-MockCalled -CommandName Test-TargetResource -Exactly 1

                }
            }

        }
        #endregion


        #region Function Set-TargetResource
        Describe "$($Global:DSCResourceName)\Test-TargetResource" {
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
        Describe "$($Global:DSCResourceName)\Set-TargetResource" {

            Context 'Identity does not exist but should' {

                Mock Invoke-Secedit
                Mock Test-TargetResource -MockWith {$true}              
                Mock Get-TargetResource -MockWith {$mockGetTargetTesult}

                It 'Should not throw' {                    

                    {Set-TargetResource @testUSR} | Should Not Throw
                }

                It 'Should call expected mocks' {

                    Assert-MockCalled -CommandName Invoke-Secedit -Exactly 1
                    Assert-MockCalled -CommandName Get-TargetResource -Exactly 1
                    Assert-MockCalled -CommandName Test-TargetResource -Exactly 1

                }

                It 'Should return updated policy' {

                    $cloneTestUSR = $testUSR.Clone()
                    
                    $cloneTestUSR.Add('PassThru',$true)

                    $setResults = Set-TargetResource @cloneTestUSR

                    $setResults.Identity | Should Be $cloneTestUSR.Identity

                }

            }

            Context 'Idenity is NULL (Remove all identites from policy)' {

                Mock Invoke-Secedit
                Mock Test-TargetResource -MockWith {$true}              
                Mock Get-TargetResource -MockWith {$mockGetTargetTesult}

                It 'Identity is NULL should remove all' {

                    $nullUSR = $testUSR.Clone()
                    $nullUSR.Identity = 'NULL'
                    $nullUSR.Add('PassThru',$true)

                    $setResults = Set-TargetResource @nullUSR

                    $setResults.Identity | Should Be ''

                }

                It 'Should call expected mocks' {

                    Assert-MockCalled -CommandName Invoke-Secedit -Exactly 1
                    Assert-MockCalled -CommandName Get-TargetResource -Exactly 1
                    Assert-MockCalled -CommandName Test-TargetResource -Exactly 1

                }            

            }

            Context 'Remove only one identity from policy when multiple are assigned' {

                $testUSR = [PSObject]@{
                    Policy         = 'Access_Credential_Manager_as_a_trusted_caller'                
                    Identity       = 'contoso\TestUser1'
                    Ensure         = 'Absent'
                    PassThru       = $true
                }

                $mockGetTargetResult = [PSObject] @{
                    Policy = 'Access_Credential_Manager_as_a_trusted_caller'
		            Identity = 'contoso\TestUser1'
                    Ensure = 'Present'
                    ActualIdentity = 'contoso\TestUser1','contoso\TestUser2'
                }

                Mock Invoke-Secedit
                Mock Test-TargetResource -MockWith {$true}              
                Mock Get-TargetResource -MockWith {$mockGetTargetResult}

                It 'Should Remove only specified Identity from Policy' {


                    $expectedResult = 'contoso\testuser2'

                    $setResult = Set-TargetResource @testUSR

                    $setResult.Identity | Should be $expectedResult

                }

                It 'Should call expected mocks' {

                    Assert-MockCalled -CommandName Invoke-Secedit -Exactly 1
                    Assert-MockCalled -CommandName Get-TargetResource -Exactly 1
                    Assert-MockCalled -CommandName Test-TargetResource -Exactly 1

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

    # TODO: Other Optional Cleanup Code Goes Here...
}

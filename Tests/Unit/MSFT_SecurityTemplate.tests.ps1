
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
    -DSCResourceName 'MSFT_SecurityTemplate' `
    -TestType Unit 

#endregion HEADER

function Invoke-TestCleanup {
    Restore-TestEnvironment -TestEnvironment $TestEnvironment    
}

# Begin Testing
try
{ 
    InModuleScope 'MSFT_SecurityTemplate' {
        $securityModulePresent = Get-Module -Name SecurityCmdlets -ListAvailable
        $testParameters = @{
            Path = 'C:\baseline.inf'
            IsSingleInstance = 'Yes'
        }

        function Set-HashValue
        {  
            param
            (
                $HashTable,
                $Key,
                $NewValue
            )

            ($HashTable.'Privilege Rights').Remove($key)
            ($HashTable.'Privilege Rights').Add($Key,$NewValue)
            $HashTable
        }

        Describe 'The system is not in a desired state' {

           # $securityModulePresent = Get-Module -Name SecurityCmdlets -ListAvailable
            $mockResults = Import-Clixml -Path "$PSScriptRoot...\..\..\Misc\MockObjects\MockResults.xml"
            $modifiedMockResults = Import-Clixml -Path "$PSScriptRoot...\..\..\Misc\MockObjects\MockResults.xml"

            Context 'Get and Test method tests' {
                Mock -CommandName Get-SecurityTemplate -MockWith {}
                Mock -CommandName Test-Path -MockWith {$true}                    
                Mock -CommandName Get-Module -MockWith {}

                if($securityModulePresent)
                {
                    Mock -CommandName Backup-SecurityPolicy -MockWith {}
                }

                It 'Should return path of desired inf' {
                    
                    $getResult = Get-TargetResource @testParameters
                    $getResult.Path | Should BeLike "*.inf"
                }

                It 'Test method should return FALSE' {  

                    foreach($key in $mockResults.'Privilege Rights'.keys)
                    {                        
                        $mockFalseResults = Set-HashValue -HashTable $modifiedMockResults -Key $key -NewValue NoIdentity
                        Mock -CommandName Get-UserRightsAssignment -MockWith {return $mockResults} -ParameterFilter {$FilePath -like "*\Temp\inf*inf"}
                        Mock -CommandName Get-UserRightsAssignment -MockWith {return $mockFalseResults} -ParameterFilter {$FilePath -eq $testParameters.Path} 

                        Test-TargetResource -Path @testParameters | Should Be $false
                    }
                }
            }

            Context 'Set method tests' {
                if($securityModulePresent)
                {
                    Mock Restore-SecurityPolicy  -MockWith {}
                }
                    Mock Invoke-Secedit -MockWith {}
                    Mock Invoke-Secedit -MockWith {}
                    Mock Test-TargetResource -MockWith {$true}

                It 'Should call Invoke-Secedit when SecurityCmdlet module does not exist' {
                    
                    Mock Get-Module -MockWith {$false}                 

                    {Set-TargetResource @testParameters} | Should Not throw
                    Assert-MockCalled -CommandName Invoke-Secedit -Exactly 1
                }

                if($securityModulePresent)
                {
                    It 'Should Call Restore-SecurityPolicy when SecurityCmdlet module does exist' {
                        Mock Get-Module -MockWith {$true}
                        {Set-TargetResource -Path @testParameters} | Should Not throw
                        Assert-MockCalled -CommandName Restore-SecurityPolicy -Exactly 1                    
                    }
                }
            }
        }

        Describe 'The system is in a desired state' {
            Context 'Test for Test method' {
                $mockResults = Import-Clixml -Path "$PSScriptRoot...\..\..\Misc\MockObjects\MockResults.xml"

                It 'Test method should return TRUE' {
                    Mock -CommandName Get-UserRightsAssignment -MockWith {$mockResults}
                    Mock -CommandName Get-SecurityTemplate -MockWith {}
                    Mock -CommandName Test-Path -MockWith {$true}
                    Mock -CommandName Get-UserRightsAssignment -MockWith {}
                    Mock -CommandName Get-Module -MockWith {}
                    
                    if($securityModulePresent)
                    {
                        Mock -CommandName Backup-SecurityPolicy -MockWith {}
                    }

                    Test-TargetResource @testParameters | should be $true
                       
                }
            }
        }        
    }
}

finally
{
    Invoke-TestCleanup
}

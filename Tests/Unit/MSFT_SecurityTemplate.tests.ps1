
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

            $securityModulePresent = Get-Module -Name SecurityCmdlets -ListAvailable
            $mockResults = Import-Clixml -Path "$PSScriptRoot...\..\..\Misc\MockObjects\MockResults.xml"
            $modifiedMockResults = Import-Clixml -Path "$PSScriptRoot...\..\..\Misc\MockObjects\MockResults.xml"

            Context 'Get and Test method tests' {
                Mock -CommandName Get-SecurityTemplate -MockWith {}
                Mock -CommandName Test-Path -MockWith {$true}                                  

                if($securityModulePresent)
                {
                    Mock -CommandName Backup-SecurityPolicy -MockWith {}
                    Mock -CommandName Get-Module -MockWith {return $true}
                    Mock -CommandName Format-SecurityPolicyFile -MockWith {"file.inf"}

                    It 'Get method should return path of inf with SecurityCmdlets' { 
                        $getResult = Get-TargetResource @testParameters
                        $getResult.Path | Should BeLike "*.inf"

                        Assert-MockCalled -CommandName Format-SecurityPolicyFile -Exactly 1
                    }
                }
                else
                {
                    It 'Get method should return path of desired inf without SecurityCmdlets' {
                        Mock -CommandName Get-Module -MockWith {$false}
                    
                        $getResult = Get-TargetResource @testParameters
                        $getResult.Path | Should BeLike "*.inf"

                        Assert-MockCalled -CommandName Get-SecurityTemplate
                    }
                }

                It 'Test method should throw if inf not found' {
                    Mock -CommandName Test-Path -MockWith {$false}
                    {Set-TargetResource @testParameters} | should throw
                }        
                foreach($key in $mockResults.'Privilege Rights'.Keys)
                {                        
                    $mockFalseResults = Set-HashValue -HashTable $modifiedMockResults -Key $key -NewValue NoIdentity
                    
                    Mock -CommandName Get-UserRightsAssignment -MockWith {return $mockResults} -ParameterFilter {$FilePath -like "*Temp*inf*inf"}
                    Mock -CommandName Get-UserRightsAssignment -MockWith {return $mockFalseResults} -ParameterFilter {$FilePath -eq $testParameters.Path} 
                    Mock -CommandName Test-Path -MockWith {$true}
                    It "Test method should return FALSE when testing $key" {  
                        Test-TargetResource @testParameters | Should Be $false
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
                        {Set-TargetResource @testParameters} | Should Not throw
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
        
        Describe 'Test helper functions' {
            Context 'Test Format-SecurityPolicyFile' {
                It 'Should not throw' {
                    Mock Get-Content -MockWith {@('Line1','Line2')}
                    Mock Out-File -MockWith {}
                    Mock Select-String -MockWith {}
                    {Format-SecurityPolicyFile -Path 'policy.inf'} | Should Not throw
                }
            }

            Context 'Test ConvertTo-LocalFriendlyName' {
                $sid = 'S-1-5-32-544'
                It 'Should equal BUILTIN\Administrators' {
                    ConvertTo-LocalFriendlyName -SID $sid | should be 'BUILTIN\Administrators'
                }

                It "Should return $env:USERDOMAIN\user1" {                    
                    Mock -CommandName Get-WmiObject -MockWith {return @{DomainRole=4}} -ModuleName SecurityPolicyResourceHelper
                    ConvertTo-LocalFriendlyName -SID 'user1' | Should be "$env:USERDOMAIN\user1"
                }

                It 'Should ignore SID translation' {
                    Mock -CommandName Get-WmiObject -MockWith {return @{DomainRole=2}} -ModuleName SecurityPolicyResourceHelper
                    ConvertTo-LocalFriendlyName -SID 'user1' | Should be 'user1'
                }
            }
            Context 'Test Invoke-Secedit' {
                Mock Start-Process -MockWith {}
                $invokeSeceditParameters = @{
                    UserRightsToAddInf = 'temp.inf'
                    SeceditOutput      = 'output.txt'
                    OverWrite          = $true
                }

                It 'Should not throw' {
                    {Invoke-Secedit @invokeSeceditParameters} | Should not throw
                }
            }
            Context 'Test Get-UserRightsAssignment' {               
                $ini = "$PSScriptRoot..\..\..\\Misc\TestHelpers\TestIni.txt"
                 Mock ConvertTo-LocalFriendlyName -MockWith {}

                 $results = Get-UserRightsAssignment $ini

                 It 'INI Section should match' {
                     $results.Keys | Should Be 'section'
                 }
                 
                 It 'INI Comment should match' {
                     $results.section.Comment1 | Should Be '; this is a comment'
                 }

                 It 'INI value should match' {
                     $results.section.Key1 | SHould be 'Value1'
                 }
            }
        }     
    }
}
finally
{
    Invoke-TestCleanup
}

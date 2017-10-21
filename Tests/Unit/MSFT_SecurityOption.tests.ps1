
#region HEADER

# Unit Test Template Version: 1.2.1
$script:moduleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if ( (-not (Test-Path -Path (Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests'))) -or `
     (-not (Test-Path -Path (Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests\TestHelper.psm1'))) )
{
    & git @('clone','https://github.com/PowerShell/DscResource.Tests.git',(Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests'))
}

Import-Module -Name (Join-Path -Path $script:moduleRoot -ChildPath (Join-Path -Path 'DSCResource.Tests' -ChildPath 'TestHelper.psm1')) -Force

$TestEnvironment = Initialize-TestEnvironment `
    -DSCModuleName 'SecurityPolicyDsc' `
    -DSCResourceName 'MSFT_SecurityOption' `
    -TestType Unit

#endregion HEADER

function Invoke-TestCleanup {
    Restore-TestEnvironment -TestEnvironment $TestEnvironment
}

# Begin Testing
try
{
    InModuleScope 'MSFT_SecurityOption' {
        
        $dscResourceInfo = Get-DscResource -Name SecurityOption
        $testParameters = @{
            Name = 'Test'
            User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users = 'Automatically deny elevation request'
            Accounts_Administrator_account_status = 'Enabled'
        }

        Describe 'SecurityOptionHelperTests' {
            Context 'Get-PolicyOptionData' {
                $dataFilePath = Join-Path -Path $dscResourceInfo.ParentPath -ChildPath SecurityOptionData.psd1
                $securityOptionData = Get-PolicyOptionData -FilePath $dataFilePath.Normalize()
                $securityOptionPropertyList    = $dscResourceInfo.Properties | Where-Object -FilterScript { $PSItem.Name -match '_' }

                It 'Should have the same count as property count' {
                    $securityOptionDataPropertyCount = $securityOptionData.Count                    
                    $securityOptionDataPropertyCount | Should Be $securityOptionPropertyList.Name.Count
                }

                foreach ( $name in $securityOptionData.Keys )
                {
                    It "Should contain property name: $name" {                        
                        $securityOptionPropertyList.Name -contains $name | Should Be $true                        
                    }
                }
                
                $optionData = Get-PolicyOptionData -FilePath $dataFilePath.Normalize()
                
                foreach ($option in $optionData.GetEnumerator())
                {
                    Context "$($option.Name)"{
                        $options = $option.Value.Option
                    
                        foreach ($entry in $options.GetEnumerator())
                        {
                            It "$($entry.Name) Should have string as Option type" {
                                $entry.value.GetType().Name -is [string] | Should Be $true
                            }
                        }
                    }
                }                
            }

            Context 'Add-PolicyOption' {
                It 'Should have [Registry Values]' {
                    [string[]]$testString = "Registry\path"
                    [string]$addOptionResult = Add-PolicyOption -RegistryPolicies $testPath

                    $addOptionResult | Should Match '[Registry Values]'
                }
                It 'Should have [System Access]' {
                    [string[]]$testString = "EnableAdminAccount=1"
                    [string]$addOptionResult = Add-PolicyOption -SystemAccessPolicies $testPath

                    $addOptionResult | Should Match '[System Access]'
                }
            }

            Context 'Format-LogonMessage' {
                $singleLineMessage = 'Line 1 - Message for line 1.,Line 2 - Message for line 2"," words"," seperated"," with"," commas.,Line 3 - Message for line 3.'
                $multiLineMessage = @'
                Line 1 - Message for line 1.
                Line 2 - Message for line 2, words, seperated, with, commas.
                Line 3 - Message for line 3.
'@
                It 'Should return a string' {
                    $result = Format-LogonMessage -Message $multiLineMessage
                    $result -is [string] | Should be $true
                }
                It 'Should match SingleLineMessage' {
                    $result = Format-LogonMessage -Message $multiLineMessage
                    $result -eq $singleLineMessage | Should be $true
                }
            }
        }
        Describe 'Get-TargetResource' {
            Context 'General operation tests' {
                It 'Should not throw' {
                    { Get-TargetResource -Name Test } | Should Not throw
                }

                It 'Should return one hashTable' {
                    $getTargetResult = Get-TargetResource -Name Test

                    $getTargetResult.GetType().BaseType.Name | Should Not Be 'Array'
                    $getTargetResult.GetType().Name | Should Be 'Hashtable'
                }
            }
        }
        Describe 'Test-TargetResource' {
            $falseMockResult = @{
                User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users = 'Prompt for crendentials'
            }
            Context 'General operation tests' {
                It 'Should return a bool' {
                    $testResult = Test-TargetResource @testParameters
                    $testResult -is [bool] | Should Be $true
                }
            }
            Context 'Not in a desired state' {
                It 'Should return false when NOT in desired state' {
                    Mock -CommandName Get-TargetResource -MockWith { $falseMockResult }
                    $testResult = Test-TargetResource @testParameters
                    $testResult | Should Be $false
                }
            }
            Context 'In a desired State' {
                $trueMockResult = $testParameters.Clone()
                $trueMockResult.Remove('Name')
                It 'Should return true when in desired state' {
                    Mock -CommandName Get-TargetResource -MockWith { $trueMockResult }
                    $testResult = Test-TargetResource @testParameters
                    $testResult | Should Be $true
                }
            }
        }
        Describe 'Set-TargetResource' {
            Mock -CommandName Invoke-Secedit -MockWith {}
            
            Context 'Successfully applied security policy' {
                Mock -CommandName Test-TargetResource -MockWith { $true }
                It 'Should not throw when successfully updated security option' {
                    { Set-TargetResource @testParameters } | Should Not throw
                }
                
                It 'Should call Test-TargetResource 2 times' {
                    Assert-MockCalled -CommandName Test-TargetResource -Times 2
                }
            }
            Context 'Failed to apply security policy' {
                Mock -CommandName Test-TargetResource -MockWith { $false }
                It 'Should throw when failed to apply security policy' {
                    { Set-TargetResource @testParameters } | Should throw
                }

                It 'Should call Test-TargetResource 2 times' {
                    Assert-MockCalled -CommandName Test-TargetResource -Times 2
                }
            }

            It "Should call Invoke-Secedit 2 times" {
                Assert-MockCalled -CommandName Invoke-Secedit -Times 2                
            }            
        }
    }
}
finally
{
    Invoke-TestCleanup
}

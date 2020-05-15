$script:dscModuleName = 'SecurityPolicyDsc'
$script:dscResourceName = 'MSFT_AccountPolicy'

function Invoke-TestSetup
{
    try
    {
        Import-Module -Name DscResource.Test -Force -ErrorAction 'Stop'
    }
    catch [System.IO.FileNotFoundException]
    {
        throw 'DscResource.Test module dependency not found. Please run ".\build.ps1 -Tasks build" first.'
    }

    $script:testEnvironment = Initialize-TestEnvironment `
        -DSCModuleName $script:dscModuleName `
        -DSCResourceName $script:dscResourceName `
        -ResourceType 'Mof' `
        -TestType 'Unit'
}

function Invoke-TestCleanup
{
    Restore-TestEnvironment -TestEnvironment $script:testEnvironment
}

Invoke-TestSetup

try
{
    InModuleScope 'MSFT_AccountPolicy' {
        
        $dscResourceInfo = Get-DscResource -Name AccountPolicy -Module SecurityPolicyDsc
        $testParameters = @{
            Name = 'Test'
            Maximum_Password_Age = '15'
            Store_passwords_using_reversible_encryption = 'Enabled'
        }

        Describe 'SecurityOptionHelperTests' {
            Context 'Get-AccountPolicyData' {
                $dataFilePath = Join-Path -Path $dscResourceInfo.ParentPath -ChildPath AccountPolicyData.psd1
                $accountPolicyData = Get-PolicyOptionData -FilePath $dataFilePath.Normalize()
                $accountPolicyPropertyList = $dscResourceInfo.Properties | Where-Object -FilterScript { $PSItem.Name -match '_' }

                It 'Should have the same count as property count' {
                    $accountPolicyDataPropertyCount = $accountPolicyData.Count                    
                    $accountPolicyDataPropertyCount | Should Be $accountPolicyPropertyList.Name.Count
                }

                foreach ( $name in $accountPolicyData.Keys )
                {
                    It "Should contain property name: $name" {                        
                        $accountPolicyPropertyList.Name -contains $name | Should Be $true                        
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
                It 'Should have [System Access]' {
                    [string[]]$testString = "EnableAdminAccount=1"
                    [string]$addOptionResult = Add-PolicyOption -SystemAccessPolicies $testString

                    $addOptionResult | Should Match '[System Access]'
                }
                It 'Shoud have [Kerberos Policy]' {
                    [string[]]$testString = "MaxClockSkew=5"
                    [string]$addOptionResult = Add-PolicyOption -KerberosPolicies $testString

                    $addOptionResult | Should Match '[Kerberos Policy]'    
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

            Context 'When MaximumPasswordAge is -1' {
                $securityPolicyMock = @{
                    'System Access' = @{ MaximumPasswordAge = -1}
                }
                Mock -CommandName 'Get-SecurityPolicy' -MockWith {$securityPolicyMock}
                It 'Should return 0' {
                    $getResult = Get-TargetResource -Name Test
                    $getResult.Maximum_Password_Age | Should Be 0
                }
            }

            Context 'When AccountLockoutDuration is -1' {
                $securityPolicyMock = @{
                    'System Access' = @{ AccountLockoutDuration = -1}
                }
                Mock -CommandName 'Get-SecurityPolicy' -MockWith {$securityPolicyMock}
                It 'Should return 0' {
                    $getResult = Get-TargetResource -Name Test
                    $getResult.Account_lockout_duration | Should Be 0
                }
            }
        }
        Describe 'Test-TargetResource' {
            $falseMockResult = @{
                Store_passwords_using_reversible_encryption = 'Disabled'
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
            Mock -CommandName Invoke-Secedit
            
            Context 'Successfully applied account policy' {
                Mock -CommandName Test-TargetResource -MockWith { $true }
                It 'Should not throw when successfully updated account policy' {
                    { Set-TargetResource @testParameters } | Should Not throw
                }
                
                It 'Should call Test-TargetResource 2 times' {
                    Assert-MockCalled -CommandName Test-TargetResource -Times 2
                }
            }
            Context 'Failed to apply account policy' {
                Mock -CommandName Test-TargetResource -MockWith { $false }
                It 'Should throw when failed to apply account policy' {
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

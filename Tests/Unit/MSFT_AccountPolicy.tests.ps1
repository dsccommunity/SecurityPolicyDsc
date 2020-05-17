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
        Set-StrictMode -Version 1.0

        $resourceName='AccountPolicy'
        $dscResourceInfo = Get-DscResource -Name AccountPolicy -Module SecurityPolicyDsc
        $testParameters = @{
            Name                                        = $resourceName
            Maximum_Password_Age                        = '15'
            Account_lockout_duration                    = '30'
            Store_passwords_using_reversible_encryption = 'Enabled'
        }

        Describe 'SecurityOptionHelperTests' {
            Context 'Get-AccountPolicyData' {
                BeforeAll {
                    $dataFilePath = Join-Path -Path $dscResourceInfo.ParentPath -ChildPath AccountPolicyData.psd1
                    $accountPolicyData = Get-PolicyOptionData -FilePath $dataFilePath.Normalize()
                    $accountPolicyPropertyList = $dscResourceInfo.Properties |
                        Where-Object -FilterScript { $PSItem.Name -match '_' }
                }

                It 'Should have the same count as property count' {
                    $accountPolicyDataPropertyCount = $accountPolicyData.Count
                    $accountPolicyDataPropertyCount | Should -Be $accountPolicyPropertyList.Name.Count
                }

                foreach ($name in $accountPolicyData.Keys)
                {
                    It "Should contain property name: $name" {
                        $accountPolicyPropertyList.Name -contains $name | Should -BeTrue
                    }
                }

                foreach ($option in $accountPolicyData.GetEnumerator())
                {
                    Context "$($option.Name)"{
                        $options = $option.Value.Option

                        foreach ($entry in $options.GetEnumerator())
                        {
                            It "$($entry.Name) Should have string as Option type" {
                                $entry.value | Should -BeOfType System.String
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
                    { Get-TargetResource -Name Test } | Should -Not -Throw
                }

                It 'Should return one hashTable' {
                    $getTargetResult = Get-TargetResource -Name Test

                    $getTargetResult | Should -Not -BeOfType System.Array
                    $getTargetResult | Should -BeOfType System.Collections.Hashtable
                }
            }

            Context 'When MaximumPasswordAge is -1' {
                BeforeAll {
                    $securityPolicyMock = @{
                        'System Access' = @{
                            MaximumPasswordAge = -1
                        }
                    }
                    Mock -CommandName 'Get-SecurityPolicy' -MockWith {$securityPolicyMock}
                }

                It 'Should return 0' {
                    $getResult = Get-TargetResource -Name Test
                    $getResult.Maximum_Password_Age | Should -Be 0
                }
            }

            Context 'When AccountLockoutDuration is -1' {
                BeforeAll {
                    $securityPolicyMock = @{
                        'System Access' = @{
                            AccountLockoutDuration = -1
                        }
                    }
                    Mock -CommandName 'Get-SecurityPolicy' -MockWith {$securityPolicyMock}
                }

                It 'Should return 0' {
                    $getResult = Get-TargetResource -Name Test
                    $getResult.Account_lockout_duration | Should -Be 0
                }
            }
        }
        Describe 'Test-TargetResource' {
            BeforeAll {
                $falseMockResult = @{
                    Store_passwords_using_reversible_encryption = 'Disabled'
                }
            }

            Context 'General operation tests' {
                It 'Should return a bool' {
                    $testResult = Test-TargetResource @testParameters
                    $testResult | Should -BeOfType System.Boolean
                }
            }

            Context 'When the resource is not in the desired state' {
                BeforeAll {
                    Mock -CommandName Get-TargetResource -MockWith { $falseMockResult }
                }

                It 'Should return false' {
                    $testResult = Test-TargetResource @testParameters
                    $testResult | Should -BeFalse
                }
            }

            Context 'When the resource is in the desired State' {
                BeforeAll {
                    $trueMockResult = $testParameters.Clone()
                    $trueMockResult.Remove('Name')

                    Mock -CommandName Get-TargetResource -MockWith { $trueMockResult }
                }

                It 'Should return true' {
                    $testResult = Test-TargetResource @testParameters
                    $testResult | Should -BeTrue
                }
            }
        }

        Describe 'Set-TargetResource' {
            BeforeAll {
                Mock -CommandName Invoke-Secedit
                Mock -CommandName Out-File -RemoveParameterType Encoding
                Mock -CommandName Remove-Item
            }

            Context 'When successfully applying the account policy' {
                BeforeAll {
                    Mock -CommandName Test-TargetResource `
                        -ParameterFilter { $Name -eq 'Test' } `
                        -MockWith { $false }
                    Mock -CommandName Test-TargetResource `
                        -ParameterFilter { $Name -eq $ResourceName } `
                        -MockWith { $true }
                }

                It 'Should not throw' {
                    { Set-TargetResource @testParameters } | Should -Not -Throw
                }

                It 'Should call the expected mocks' {
                    Assert-MockCalled -CommandName Test-TargetResource `
                       -ParameterFilter { $Name -eq 'Test' } `
                        -Exactly -Times ($testParameters.Count-1)
                    Assert-MockCalled -CommandName Test-TargetResource `
                        -ParameterFilter { $Name -eq $resourceName } `
                         -Exactly -Times 1
                     Assert-MockCalled -CommandName Out-File `
                        -ParameterFilter {
                            $InputObject -contains "MaximumPasswordAge=$($testParameters.Maximum_Password_Age)" -and
                            $InputObject -contains "LockoutDuration=$($testParameters.Account_lockout_duration)" -and
                            $InputObject -contains "ClearTextPassword=1"
                        } `
                        -Exactly -Times 1
                    Assert-MockCalled -CommandName Invoke-Secedit -Exactly -Times 1
                    Assert-MockCalled -CommandName Remove-Item -Exactly -Times 1
        }

                Context 'When Maximum_password_age is Zero' {
                    BeforeAll {
                        $testMaxPasswordAgeParameters=$testParameters.Clone()
                        $testMaxPasswordAgeParameters.Maximum_password_age = 0
                    }

                    It 'Should not throw' {
                        { Set-TargetResource @testMaxPasswordAgeParameters } | Should -Not -Throw
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Test-TargetResource `
                           -ParameterFilter { $Name -eq 'Test' } `
                            -Exactly -Times ($testParameters.Count-1)
                        Assert-MockCalled -CommandName Test-TargetResource `
                            -ParameterFilter { $Name -eq $resourceName } `
                             -Exactly -Times 1
                        Assert-MockCalled -CommandName Out-File `
                            -ParameterFilter { $InputObject -contains 'MaximumPasswordAge=-1' } `
                            -Exactly -Times 1
                        Assert-MockCalled -CommandName Invoke-Secedit -Exactly -Times 1
                        Assert-MockCalled -CommandName Remove-Item -Exactly -Times 1
                    }
                }

                Context 'When Account_lockout_duration is Zero' {
                    BeforeAll {
                        $testAccountLockoutDurationParameters=$testParameters.Clone()
                        $testAccountLockoutDurationParameters.Account_lockout_duration = 0
                    }

                    It 'Should not throw' {
                        { Set-TargetResource @testAccountLockoutDurationParameters } | Should -Not -Throw
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Test-TargetResource `
                            -ParameterFilter { $Name -eq 'Test' } `
                            -Exactly -Times ($testParameters.Count-1)
                        Assert-MockCalled -CommandName Test-TargetResource `
                            -ParameterFilter { $Name -eq $resourceName } `
                             -Exactly -Times 1
                        Assert-MockCalled -CommandName Out-File `
                            -ParameterFilter { $InputObject -contains 'LockoutDuration=-1' } `
                            -Exactly -Times 1
                        Assert-MockCalled -CommandName Invoke-Secedit -Exactly -Times 1
                        Assert-MockCalled -CommandName Remove-Item -Exactly -Times 1
                    }
                }
            }

            Context 'When failing to apply the account policy' {
                BeforeAll {
                    $testFailedParameters=$testParameters.Clone()
                    $testFailedParameters.Remove('Name')
                    $testFailedParameterKeys=$testFailedParameters.Keys | Sort-Object

                    Mock -CommandName Test-TargetResource `
                        -ParameterFilter { $Name -eq 'Test' } `
                        -MockWith { $false }
                    Mock -CommandName Test-TargetResource `
                        -ParameterFilter { $Name -eq $ResourceName } `
                        -MockWith { $false }
                }

                It 'Should throw the correct exception' {
                    { Set-TargetResource @testParameters } | Should -Throw ($script:localizedData.SetFailed -f
                        ($testFailedParameterkeys -join ','))
                }

                It 'Should call the expected mocks' {
                    Assert-MockCalled -CommandName Test-TargetResource `
                        -ParameterFilter { $Name -eq 'Test' } `
                        -Exactly -Times ($testParameters.Count-1)
                    Assert-MockCalled -CommandName Test-TargetResource `
                        -ParameterFilter { $Name -eq $resourceName } `
                         -Exactly -Times 1
                    Assert-MockCalled -CommandName Out-File -Exactly -Times 1
                    Assert-MockCalled -CommandName Invoke-Secedit -Exactly -Times 1
                    Assert-MockCalled -CommandName Remove-Item -Exactly -Times 1
                }
            }
        }
    }
}
finally
{
    Invoke-TestCleanup
}

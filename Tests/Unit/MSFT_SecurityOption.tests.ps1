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

# Unit Test Template Version: 1.2.1
$script:moduleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if ( (-not (Test-Path -Path (Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests'))) -or `
     (-not (Test-Path -Path (Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests\TestHelper.psm1'))) )
{
    & git @('clone','https://github.com/PowerShell/DscResource.Tests.git',(Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests'))
}

Import-Module -Name (Join-Path -Path $script:moduleRoot -ChildPath (Join-Path -Path 'DSCResource.Tests' -ChildPath 'TestHelper.psm1')) -Force

# TODO: Insert the correct <ModuleName> and <ResourceName> for your resource
$TestEnvironment = Initialize-TestEnvironment `
    -DSCModuleName 'SecurityPolicyDsc' `
    -DSCResourceName 'MSFT_SecurityOption' `
    -TestType Unit

#endregion HEADER

function Invoke-TestSetup {
    # TODO: Optional init code goes here...
}

function Invoke-TestCleanup {
    Restore-TestEnvironment -TestEnvironment $TestEnvironment

    # TODO: Other Optional Cleanup Code Goes Here...
}

# Begin Testing
try
{
    Invoke-TestSetup

    InModuleScope 'MSFT_SecurityOption' {
        # TODO: Optionally create any variables here for use by your tests

        # TODO: Complete the Describe blocks below and add more as needed.
        # The most common method for unit testing is to test by function. For more information
        # check out this introduction to writing unit tests in Pester:
        # https://www.simple-talk.com/sysadmin/powershell/practical-powershell-unit-testing-getting-started/#eleventh
        # You may also follow one of the patterns provided in the TestsGuidelines.md file:
        # https://github.com/PowerShell/DscResources/blob/master/TestsGuidelines.md
        $dscResourceInfo = Get-DscResource -Name SecurityOption
        Describe 'SecurityOptionHelperTests' {
            Context 'Get-SecurityOptionData' {
                $dataFilePath = Join-Path -Path $dscResourceInfo.ParentPath -ChildPath SecurityOptionData.psd1
                $securityOptionData = Get-SecurityOptionData -FilePath $dataFilePath.Normalize()
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
                
                $optionData = Get-SecurityOptionData
                
                foreach ($option in $optionData.GetEnumerator())
                {
                    context "$($option.Name)"{
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
            Context 'General operation tests' {
                It 'Should return a bool' {
                    # test-code
                }
            }
            Context 'Not in a desired state' {
                It 'Should return false when desired value is ambiguous (string)' {
                    # test-code
                }

                It 'Should return false when desired value is Enabled or Disabled' {

                }
            }
        }
        Describe 'Set-TargetResource' {
            Context '<Context-description>' {
                It 'Should ...test-description' {
                    # test-code
                }
            }
        }
        # TODO: add more Describe blocks as needed
    }
}
finally
{
    Invoke-TestCleanup
}

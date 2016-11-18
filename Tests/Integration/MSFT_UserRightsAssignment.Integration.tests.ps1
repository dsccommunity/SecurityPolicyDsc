
$script:DSCModuleName      = 'SecurityPolicyDsc'
$script:DSCResourceName    = 'MSFT_UserRightsAssignment'

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
    -TestType Integration 
#endregion


try
{
    #region Integration Tests
    $ConfigFile = Join-Path -Path $PSScriptRoot -ChildPath "$($Global:DSCResourceName).config.ps1"
    . $ConfigFile

    Describe "$($script:DSCResourceName)_Integration" {

        $beforeTest_TrustedCaller = Get-TargetResource -Policy $rule.Policy -Identity $rule.Identity
        $beforeTest_ActAsOS       = Get-TargetResource -Policy $removeAll.Policy -Identity $removeAll.Identity

        Set-TargetResource -Policy $removeAll.Policy -Identity 'Builtin\Administrators'

        #region DEFAULT TESTS
        Context "Default Tests" {
            It 'Should compile without throwing' {
                {
                    Invoke-Expression -Command "$($Global:DSCResourceName)_Config -OutputPath `$TestEnvironment.WorkingFolder"
                    Start-DscConfiguration -Path $TestEnvironment.WorkingFolder `
                        -ComputerName localhost -Wait -Verbose -Force
                } | Should not throw
            }

            It 'Should be able to call Get-DscConfiguration without throwing' {
                { Get-DscConfiguration -Verbose -ErrorAction Stop } | Should Not throw
            }
        }
        #endregion

        Context 'Verify Successful Configuration on Trusted Caller' {

            It 'Should have set the resource and all the parameters should match' {
                $getResults = Get-TargetResource -Policy $rule.Policy -Identity $rule.Identity
                 
                foreach ($Id in $rule.Identity)
                {
                    $getResults.ActualIdentity | where {$_ -eq $Id} | Should Be $Id
                }

                $rule.Policy | Should Be $getResults.Policy
            }
        }

        Context 'Verify Success on Act as OS remove all' {

            It 'Should have set the resource and all the parameters should match' {
                $getResults = Get-TargetResource -Policy $removeAll.Policy -Identity $removeAll.Identity
                 
                foreach ($Id in $removeAll.Identity)
                {
                    $getResults.ActualIdentity | where {$_ -eq $Id} | Should Be $Id
                }

                $removeAll.Policy | Should Be $getResults.Policy
            }
        }

        Set-TargetResource -Policy $beforeTest_TrustedCaller.Policy -Identity $beforeTest_TrustedCaller.ActualIdentity -Verbose

        Set-TargetResource -Policy $beforeTest_ActAsOS.Policy -Identity $beforeTest_ActAsOS.ActualIdentity -Verbose
    }
    #endregion
}

finally
{
    #region FOOTER
    Restore-TestEnvironment -TestEnvironment $TestEnvironment
    #endregion

}


$script:DSCModuleName   = 'SecurityPolicyDsc'
$script:DSCResourceName = 'MSFT_AccountPolicy'

#region HEADER
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
    -TestType 'Integration'
#endregion

try
{
    #region Integration Tests
    $configFile = Join-Path -Path $PSScriptRoot -ChildPath "$($script:DSCResourceName).config.ps1"
    . $configFile

    Describe "$($script:DSCResourceName)_Integration" {
        #region DEFAULT TESTS
        It 'Should compile and apply the MOF without throwing' {
            {
                & "$($script:DSCResourceName)_Config" -OutputPath $TestDrive

                Start-DscConfiguration -Path $TestDrive `
                    -ComputerName localhost -Wait -Verbose -Force
            } | Should Not Throw
        }

        It 'Should be able to call Get-DscConfiguration without throwing' {
            {
                Get-DscConfiguration -Verbose -ErrorAction Stop 
            } | Should Not Throw
        }
        #endregion
        
        $currentAccountPolicies = Get-DscConfiguration
        foreach ( $key in $accountPolicies.Keys)
        {
            It "Should have set the Account Policy: $key and parameters should match" {
                $accountPolicies.$key | Should Be $currentAccountPolicies.$key
            }
        }
    }
    #endregion
}
finally
{
    #region FOOTER

    Restore-TestEnvironment -TestEnvironment $script:testEnvironment

    #endregion
}

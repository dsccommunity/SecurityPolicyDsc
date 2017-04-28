
$script:dscModuleName    = 'SecurityPolicyDsc' 
$script:dscResourceName  = 'MSFT_SecuritySetting'

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

            $getParameters = [PSObject]@{
                Name = "LockoutBadCount"       
            }          

            $falseParameters = [PSObject]@{
                LockoutBadCount = 5
                Name = "LockoutBadCount"       
            }  

            $trueParameters = [PSObject]@{
                LockoutBadCount = 10
                Name = "LockoutBadCount"       
            }

            $mockSecuritySettings = [PSObject]@{
                'System Access' = @{ 
                                    LockoutBadCount = 10
                                    Name = "LockoutBadCount"       
                                }
            }   
            
            $testParameters = [PSObject]@{    
                LockoutBadCount = 10
                Name = "LockoutBadCount"       
            }        

        #endregion

        #region Function Get-TargetResource
        Describe "Get-TargetResource" {  
            Context 'Retrieve proper Values' {
                Mock -CommandName Get-SecuritySettings -MockWith {return @($mockSecuritySettings)}
                Mock -CommandName Test-TargetResource -MockWith {$false}

                It 'Should retrieve proper values' {                    
                    $result = Get-TargetResource @getParameters

                    $result.Name | Should Be $testParameters.Name
                    $result.LockoutBadCount | Should Be $testParameters.LockoutBadCount
                }

                It 'Should call expected Mocks' {
                    Assert-MockCalled -CommandName Get-SecuritySettings -Exactly 1
                }
            }
        }
        #endregion

        #region Function Test-TargetResource
        Describe "Test-TargetResource" {
            Context 'Values Match' {
                Mock -CommandName New-Object -ParameterFilter {$TypeName -eq "System.Diagnostics.Process" } -MockWith {
                     $object = [pscustomobject]@{
                                                StartInfo=[pscustomobject]@{
                                                                            FileName="secedit.exe";
                                                                            Arguments=" /configure /db $newSecDB /cfg $tmpfile /overwrite /quiet";
                                                                            RedirectStandardOutput=$true;
                                                                            UseShellExecute=$false;
                                                                           };
                                                StandardOutput=[pscustomobject]@{
                                                                                 
                                                                                }
                                            }
                    $object = $object | Add-member -MemberType ScriptMethod -Name Start -Value { param() } -Force -PassThru
                    $object = $object | Add-member -MemberType ScriptMethod -Name WaitForExit -Value { param() } -Force -PassThru
                    $object.StandardOutput = $object.StandardOutput | Add-member -MemberType ScriptMethod -Name ReadToEnd -Value { param() } -Force -PassThru
                    return $object
                }
                Mock -CommandName Get-SecuritySettings -MockWith {return @($mockSecuritySettings)}

                It 'Should return true' {
                    $testResult = Test-TargetResource @trueParameters

                    $testResult | Should Be $true
                }

                It 'Should call expected mocks' {
                    Assert-MockCalled -CommandName Get-SecuritySettings -Exactly 1
                }
            }

            Context 'Values do not match' {
                Mock -CommandName Get-SecuritySettings -MockWith {return @($mockSecuritySettings)}

                It 'Shoud return false' {
                   $testResult = Test-TargetResource @falseParameters
                   $testResult | Should be $false
                }
            }
        }
        #endregion
        #region Function Set-TargetResource
        Describe "Set-TargetResource" {
            Context 'Explicitly Set SecuritySetting values' {
                
                 Mock -CommandName New-Object -ParameterFilter {$TypeName -eq "System.Diagnostics.Process" } -MockWith {
                     $object = [pscustomobject]@{
                                                StartInfo=[pscustomobject]@{
                                                                            FileName="secedit.exe";
                                                                            Arguments=" /configure /db $newSecDB /cfg $tmpfile /overwrite /quiet";
                                                                            RedirectStandardOutput=$true;
                                                                            UseShellExecute=$false;
                                                                           };
                                                StandardOutput=[pscustomobject]@{
                                                                                 
                                                                                }
                                            }
                    $object = $object | Add-member -MemberType ScriptMethod -Name Start -Value { param() } -Force -PassThru
                    $object = $object | Add-member -MemberType ScriptMethod -Name WaitForExit -Value { param() } -Force -PassThru
                    $object.StandardOutput = $object.StandardOutput | Add-member -MemberType ScriptMethod -Name ReadToEnd -Value { param() } -Force -PassThru
                    return $object
                }
                Mock -CommandName Get-SecuritySettings -MockWith {return @($mockSecuritySettings)}
                Mock -CommandName Test-TargetResource -MockWith {$false}
                                
                It 'Should not throw' { 
                    {Set-TargetResource @trueParameters} | Should Not Throw
                }                
                                
                It 'Should call expected mocks' {
                    Assert-MockCalled -CommandName New-Object -Exactly 1
                    Assert-MockCalled -CommandName Get-SecuritySettings -Exactly 1
                }
            }
        }
        #endregion
        #region Function Get-USRPolicy
        Describe "Get-IniContent" {
            
            $iniPath = (Join-Path -Path $PSScriptRoot -ChildPath "sample.inf")

            It 'Should not Throw' {
                {Get-IniContent -Path $iniPath} | Should Not Throw
            }
            It 'Should match values' {
                $iniResults = Get-IniContent -Path $iniPath 
                $iniResults.'System Access'.LockoutBadCount | Should be $testParameters.LockoutBadCount
            }
        }
        #endregion    
    }
    #endregion
}
catch
{
    continue
}
finally
{
    #region FOOTER
    Restore-TestEnvironment -TestEnvironment $TestEnvironment
    #endregion
}

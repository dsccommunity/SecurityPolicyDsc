<#PSScriptInfo
.VERSION 1.0.1
.GUID 6052dbbe-d7bd-46f3-9407-00ae446ef1a2
.AUTHOR DSC Community
.COMPANYNAME DSC Community
.COPYRIGHT DSC Community contributors. All rights reserved.
.TAGS DSCConfiguration
.LICENSEURI https://github.com/dsccommunity/SecurityPolicyDsc/blob/master/LICENSE
.PROJECTURI https://github.com/dsccommunity/SecurityPolicyDsc
.ICONURI https://dsccommunity.org/images/DSC_Logo_300p.png
.EXTERNALMODULEDEPENDENCIES 
.REQUIREDSCRIPTS
.EXTERNALSCRIPTDEPENDENCIES
.RELEASENOTES
Updated author, copyright notice, and URLs.
.PRIVATEDATA
#> 

#Requires -Module SecurityPolicyDsc


<#
    .DESCRIPTION
        This configuration will manage the local security account policy.
#>

Configuration AccountPolicy_Config
{
    Import-DscResource -ModuleName SecurityPolicyDsc

    node localhost
    {
        AccountPolicy 'AccountPolicies'
        {
            Name                                        = 'PasswordPolicies'
            Enforce_password_history                    = 15
            Maximum_Password_Age                        = 42
            Minimum_Password_Age                        = 1
            Minimum_Password_Length                     = 12
            Password_must_meet_complexity_requirements  = 'Enabled'
            Store_passwords_using_reversible_encryption = 'Disabled'
        }
    }
}

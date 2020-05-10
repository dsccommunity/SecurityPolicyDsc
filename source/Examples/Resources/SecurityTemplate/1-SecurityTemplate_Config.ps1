<#PSScriptInfo
.VERSION 1.0.1
.GUID 374899a2-937c-446c-9f00-6d6b930b04c8
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
        This configuration will manage user rights assignments that are defined
        in a security policy INF file.
#>
Configuration SecurityTemplate_Config
{
    Import-DscResource -ModuleName SecurityPolicyDsc

    node localhost
    {
        SecurityTemplate TrustedCredentialAccess
        {
            Path             = "C:\scratch\SecurityPolicyBackup.inf"
            IsSingleInstance = 'Yes'
        }
    }
}

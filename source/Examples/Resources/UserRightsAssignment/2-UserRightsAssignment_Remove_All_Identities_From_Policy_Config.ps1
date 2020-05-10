<#PSScriptInfo
.VERSION 1.0.1
.GUID ecc41d8a-15d0-485f-b019-fa30842f3732
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
        This configuration will manage a User Rights Assignment policy.
        When Identity is an empty string all identities will be removed from the policy.
#>
Configuration UserRightsAssignment_Remove_All_Identities_From_Policy_Config
{
    Import-DscResource -ModuleName SecurityPolicyDsc

    Node localhost
    {
        UserRightsAssignment RemoveIdsFromSeTrustedCredManAccessPrivilege
        {
            Policy   = "Access_Credential_Manager_as_a_trusted_caller"
            Identity = ""
        }
    }
}

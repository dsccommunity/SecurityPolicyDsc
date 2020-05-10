<#PSScriptInfo
.VERSION 1.0.1
.GUID b8e54087-a68d-4bca-8222-3bc34b2e857d
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
        This configuration will manage the kerberos security policies.

        Since kerberos policies are domain policies they can only be modified with
        domain admin privileges.
#>

Configuration AccountPolicy_KerberosPolicies_Config
{
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        $DomainCred
    )

    Import-DscResource -ModuleName SecurityPolicyDsc

    node localhost
    {
        AccountPolicy KerberosPolicies
        {
            Name                                                 = 'KerberosPolicies'
            Enforce_user_logon_restrictions                      = 'Enabled'
            Maximum_lifetime_for_service_ticket                  = 600
            Maximum_lifetime_for_user_ticket                     = 10
            Maximum_lifetime_for_user_ticket_renewal             = 7
            Maximum_tolerance_for_computer_clock_synchronization = 5
            PsDscRunAsCredential                                 = $DomainCred
        }
    }
}

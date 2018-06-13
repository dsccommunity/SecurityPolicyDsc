
# Since kerberos policies are domain policies they can only be modified with domain admin privileges
configuration KerberosPolicies
{
    param
    (
        [pscredential]
        $DomainCred
    )

    Import-DscResource -ModuleName SecurityPolicyDsc

    node localhost
    {
        AccountPolicy KerbPolicies
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

$configData = @{
    AllNodes = @(
        @{
            NodeName = "DC1"
            CertificateFile = "C:\publicKeys\targetNode.cer"
            Thumbprint = "AC23EA3A9E291A75757A556D0B71CBBF8C4F6FD8"
        }
    )
}

$cred = Get-Credential -Message "Enter the credentials of a domain admin"
KerberosPolicies -OutputPath C:\DSC -ConfigurationData $configData -DomainCred $cred
Start-DscConfiguration -Path C:\DSC -Wait -Force -Verbose

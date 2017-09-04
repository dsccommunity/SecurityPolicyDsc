configuration SecurityOptions
{
    Import-DscResource -ModuleName SecurityPolicyDsc

    node localhost
    {
        SecurityOption AccountSecurityOptions
        {
            Name = 'AccountSecurityOptions'
            Accounts_Guest_account_status = 'Enabled'
            Accounts_Rename_guest_account = 'NewGuest'
            Accounts_Block_Microsoft_accounts = 'This policy is disabled'
        }
    }
}

SecurityOptions -OutputPath c:\dsc 
Start-DscConfiguration -Path c:\dsc -Wait -Force -Verbose

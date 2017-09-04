configuration SecurityOptions
{
    Import-DscResource -ModuleName SecurityPolicyDsc

    node localhost
    {
        SecurityOption AccountSecurityOptions
        {
            Name = 'AccountSecurityOptions'
            Accounts_Administrator_account_status = 'Disabled'
            Accounts_Guest_account_status = 'Enabled'
            Accounts_Rename_guest_account = 'NewGuest'
            Accounts_Rename_administrator_account = 'root'
            Accounts_Block_Microsoft_accounts = 'This_policy_is_disabled'
        }
    }
}

SecurityOptions -OutputPath c:\dsc 
Start-DscConfiguration -Path c:\dsc -Wait -Force -Verbose

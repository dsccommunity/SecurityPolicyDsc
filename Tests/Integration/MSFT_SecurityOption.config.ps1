
$securityOptions = @{
    Accounts_Guest_account_status = 'Enabled'
    Accounts_Rename_guest_account = 'NewGuest'
    Accounts_Block_Microsoft_accounts = 'This policy is disabled'
}

configuration MSFT_SecurityOption_config {

    Import-DscResource -ModuleName 'SecurityPolicyDsc'

    node localhost {

        SecurityOption Integration_Test 
        {
            Name = 'IntegrationTest'
            Accounts_Guest_account_status = "$($securityOptions.Accounts_Guest_account_status)"
            Accounts_Rename_guest_account = "$($securityOptions.Accounts_Rename_guest_account)"
            Accounts_Block_Microsoft_accounts = "$($securityOptions.Accounts_Block_Microsoft_accounts)"
        }
    }
}


$rule = @{

    LockoutBadCount   = 10
    Name = 'LockoutBadCount'
}

configuration MSFT_SecuritySetting_config {
    Import-DscResource -ModuleName SecurityPolicyDsc
    
    SecuritySetting LockoutBadCount
    {
        # Assign shutdown privileges to only Builtin\Administrators
        Name   = "LockoutBadCount"
        LockoutBadCount = 10
    }
}

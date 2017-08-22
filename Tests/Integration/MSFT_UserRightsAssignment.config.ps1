
# S-1-5-6 = NT Authority\Service
# S-1-5-90-0 = 'window manager\window manager group'

$rule = @{
    Policy   = 'Access_Credential_Manager_as_a_trusted_caller'
    Identity = 'builtin\Administrators','*S-1-5-6','S-1-5-90-0'
}

$removeAll = @{    
    Policy = 'Act_as_part_of_the_operating_system'
    Identity = ""
}

$removeGuests = @{
    Policy = 'Deny_log_on_locally'
    Identity = 'Guests'
}


configuration MSFT_UserRightsAssignment_config {
    Import-DscResource -ModuleName SecurityPolicyDsc
    
    UserRightsAssignment AccessCredentialManagerAsaTrustedCaller
    {
        Policy   = $rule.Policy
        Identity = $rule.Identity
    }
    
    UserRightsAssignment RemoveAllActAsOS
    {
        Policy   = $removeAll.Policy
        Identity = $removeAll.Identity
    }

    UserRightsAssignment DenyLogOnLocally
    {
        Policy   = $removeGuests.Policy
        Identity = $removeGuests.IsFixedSize
        Ensure   = 'Present'
    }

    UserRightsAssignment DenyLogOnLocally
    {
        Policy   = $removeGuests.Policy
        Identity = $removeGuests.IsFixedSize
        Ensure   = 'Absent'
    }
}


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
}

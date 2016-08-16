<#
.Synopsis
   DSC Configuration Template for DSC Resource Integration tests.
.DESCRIPTION
   To Use:
     1. Copy to \Tests\Integration\ folder and rename MSFT_<ResourceName>.config.ps1 (e.g. MSFT_xFirewall.config.ps1)
     2. Customize TODO sections.

.NOTES
#>


$rule = @{

    Policy   = 'Access_Credential_Manager_as_a_trusted_caller'
    Identity = 'builtin\Administrators','contoso\testuser1'
}

$removeAll = @{
    
    Policy = 'Act_as_part_of_the_operating_system'
    Identity = 'NULL'
}

configuration MSFT_UserRightsAssignment_config {
    Import-DscResource -ModuleName SeceditDSC
    
    xUserRightsAssignment AccessCredentialManagerAsaTrustedCaller
    {
        #Assign shutdown privileges to only Builtin\Administrators
        Policy   = $rule.Policy
        Identity = $rule.Identity
    }
    
    UserRightsAssignment RemoveAllActAsOS
    {
        Policy   = $removeAll.Policy
        Identity = $removeAll.Identity
    }
    
}

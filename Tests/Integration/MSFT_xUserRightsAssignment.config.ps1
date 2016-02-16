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
    Identity = 'Builtin\Administrators'
    Ensure   = 'Present'
}

# TODO: Modify ResourceName
configuration MSFT_xUserRightsAssignment_config {
    Import-DscResource -ModuleName xSecedit

    xUserRightsAssignment AssignShutdownPrivlegesToAdmins
    {
        #Assign shutdown privileges to only Builtin\Administrators
        Policy = $rule.Policy
        Identity = $rule.Identity
        Ensure = $rule.Ensure
    }
    
}

# TODO: (Optional): Add More Configuration Templates


Import-Module -Name (Join-Path -Path ( Split-Path $PSScriptRoot -Parent ) `
                               -ChildPath 'SecurityPolicyResourceHelper\SecurityPolicyResourceHelper.psm1') `
                               -Force

$script:localizedData = Get-LocalizedData -ResourceName 'MSFT_UserRightsAssignment'

<#
    .SYNOPSIS
        Gets the current identities assigned to a user rights assignment.
    .PARAMETER Policy
        Specifies the policy to configure.
    .PARAMETER Identity
        Specifies the identity to add to a user rights assignment.
#>
function Get-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateSet(
            "Create_a_token_object",
            "Access_this_computer_from_the_network",
            "Change_the_system_time",
            "Deny_log_on_as_a_batch_job",
            "Deny_log_on_through_Remote_Desktop_Services",
            "Create_global_objects",
            "Remove_computer_from_docking_station",
            "Deny_access_to_this_computer_from_the_network",
            "Act_as_part_of_the_operating_system",
            "Modify_firmware_environment_values",
            "Deny_log_on_locally",
            "Access_Credential_Manager_as_a_trusted_caller",
            "Restore_files_and_directories",
            "Change_the_time_zone",
            "Replace_a_process_level_token",
            "Manage_auditing_and_security_log",
            "Create_symbolic_links",
            "Modify_an_object_label",
            "Enable_computer_and_user_accounts_to_be_trusted_for_delegation",
            "Generate_security_audits",
            "Increase_a_process_working_set",
            "Take_ownership_of_files_or_other_objects",
            "Bypass_traverse_checking",
            "Log_on_as_a_service",
            "Shut_down_the_system",
            "Lock_pages_in_memory",
            "Impersonate_a_client_after_authentication",
            "Profile_system_performance",
            "Debug_programs",
            "Profile_single_process",
            "Allow_log_on_through_Remote_Desktop_Services",
            "Allow_log_on_locally",
            "Increase_scheduling_priority",
            "Synchronize_directory_service_data",
            "Add_workstations_to_domain",
            "Adjust_memory_quotas_for_a_process",
            "Obtain_an_impersonation_token_for_another_user_in_the_same_session",
            "Perform_volume_maintenance_tasks",
            "Load_and_unload_device_drivers",
            "Force_shutdown_from_a_remote_system",
            "Back_up_files_and_directories",
            "Create_a_pagefile",
            "Deny_log_on_as_a_service",
            "Log_on_as_a_batch_job",
            "Create_permanent_shared_objects"
        )]
        [System.String]
        $Policy,

        [parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [AllowEmptyString()]      
        [System.String[]]
        $Identity
    )
    
    $usrResult = Get-USRPolicy -Policy $Policy -Areas USER_RIGHTS

    $returnValue = @{
        Policy         = $usrResult.PolicyFriendlyName
        Identity       = $usrResult.Identity
    }

    $returnValue
}

<#
    .SYNOPSIS
        Gets the current identities assigned to a user rights assignment.
    .PARAMETER Policy
        Specifies the policy to configure.
    .PARAMETER Identity
        Specifies the identity to add to a user rights assignment.
#>
function Set-TargetResource
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateSet(
            "Create_a_token_object",
            "Access_this_computer_from_the_network",
            "Change_the_system_time",
            "Deny_log_on_as_a_batch_job",
            "Deny_log_on_through_Remote_Desktop_Services",
            "Create_global_objects",
            "Remove_computer_from_docking_station",
            "Deny_access_to_this_computer_from_the_network",
            "Act_as_part_of_the_operating_system",
            "Modify_firmware_environment_values",
            "Deny_log_on_locally",
            "Access_Credential_Manager_as_a_trusted_caller",
            "Restore_files_and_directories",
            "Change_the_time_zone",
            "Replace_a_process_level_token",
            "Manage_auditing_and_security_log",
            "Create_symbolic_links",
            "Modify_an_object_label",
            "Enable_computer_and_user_accounts_to_be_trusted_for_delegation",
            "Generate_security_audits",
            "Increase_a_process_working_set",
            "Take_ownership_of_files_or_other_objects",
            "Bypass_traverse_checking",
            "Log_on_as_a_service",
            "Shut_down_the_system",
            "Lock_pages_in_memory",
            "Impersonate_a_client_after_authentication",
            "Profile_system_performance",
            "Debug_programs",
            "Profile_single_process",
            "Allow_log_on_through_Remote_Desktop_Services",
            "Allow_log_on_locally",
            "Increase_scheduling_priority",
            "Synchronize_directory_service_data",
            "Add_workstations_to_domain",
            "Adjust_memory_quotas_for_a_process",
            "Obtain_an_impersonation_token_for_another_user_in_the_same_session",
            "Perform_volume_maintenance_tasks",
            "Load_and_unload_device_drivers",
            "Force_shutdown_from_a_remote_system",
            "Back_up_files_and_directories",
            "Create_a_pagefile",
            "Deny_log_on_as_a_service",
            "Log_on_as_a_batch_job",
            "Create_permanent_shared_objects"
        )]
        [System.String]
        $Policy,

        [parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [AllowEmptyString()]
        [System.String[]]
        $Identity
    )
    
    $policyList = Get-AssignmentFriendlyNames
    $policyName = $policyList[$Policy]
    $script:seceditOutput = "$env:TEMP\Secedit-OutPut.txt"
    $userRightsToAddInf = "$env:TEMP\userRightsToAdd.inf" 
    $idsToAdd = $Identity -join ","

    if ($null -eq $Identity)
    {
        Write-Verbose -Message ($script:localizedData.IdentityIsNullRemovingAll -f $Policy)
        $idsToAdd = $null
    }
    else
    {
        Write-Verbose -Message ($script:localizedData.GrantingPolicyRightsToIds -f $Policy, $idsToAdd)
    }
       
    Out-UserRightsInf -InfPolicy $policyName -UserList $idsToAdd -FilePath $userRightsToAddInf
    Write-Debug -Message ($script:localizedData.EchoDebugInf -f $userRightsToAddInf)

    Invoke-Secedit -UserRightsToAddInf $userRightsToAddInf -SecEditOutput $seceditOutput
    
    # Verify secedit command was successful

    if (Test-TargetResource -Identity $Identity -Policy $Policy)
    {
        Write-Verbose -Message ($script:localizedData.TaskSuccess)
    }
    else
    {
        $seceditResult = Get-Content -Path $script:seceditOutput
        Write-Verbose -Message ($script:localizedData.TaskFail)
        throw "$($script:localizedData.TaskFail) $($seceditResult[-1])"
    }    
}

<#
    .SYNOPSIS
        Gets the current identities assigned to a user rights assignment.
    .PARAMETER Policy
        Specifies the policy to configure.
    .PARAMETER Identity
        Specifies the identity to add to a user rights assignment.
#>
function Test-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateSet(
            "Create_a_token_object",
            "Access_this_computer_from_the_network",
            "Change_the_system_time",
            "Deny_log_on_as_a_batch_job",
            "Deny_log_on_through_Remote_Desktop_Services",
            "Create_global_objects",
            "Remove_computer_from_docking_station",
            "Deny_access_to_this_computer_from_the_network",
            "Act_as_part_of_the_operating_system",
            "Modify_firmware_environment_values",
            "Deny_log_on_locally",
            "Access_Credential_Manager_as_a_trusted_caller",
            "Restore_files_and_directories",
            "Change_the_time_zone",
            "Replace_a_process_level_token",
            "Manage_auditing_and_security_log",
            "Create_symbolic_links",
            "Modify_an_object_label",
            "Enable_computer_and_user_accounts_to_be_trusted_for_delegation",
            "Generate_security_audits",
            "Increase_a_process_working_set",
            "Take_ownership_of_files_or_other_objects",
            "Bypass_traverse_checking",
            "Log_on_as_a_service",
            "Shut_down_the_system",
            "Lock_pages_in_memory",
            "Impersonate_a_client_after_authentication",
            "Profile_system_performance",
            "Debug_programs",
            "Profile_single_process",
            "Allow_log_on_through_Remote_Desktop_Services",
            "Allow_log_on_locally",
            "Increase_scheduling_priority",
            "Synchronize_directory_service_data",
            "Add_workstations_to_domain",
            "Adjust_memory_quotas_for_a_process",
            "Obtain_an_impersonation_token_for_another_user_in_the_same_session",
            "Perform_volume_maintenance_tasks",
            "Load_and_unload_device_drivers",
            "Force_shutdown_from_a_remote_system",
            "Back_up_files_and_directories",
            "Create_a_pagefile",
            "Deny_log_on_as_a_service",
            "Log_on_as_a_batch_job",
            "Create_permanent_shared_objects"
        )]
        [System.String]
        $Policy,

        [parameter(Mandatory = $true)]
        [AllowEmptyCollection()] 
        [AllowEmptyString()]               
        [System.String[]]
        $Identity
    )
        
    $userRights = Get-USRPolicy -Policy $Policy -Areas USER_Rights    

    if ($null -eq $Identity -or [System.String]::IsNullOrWhiteSpace($Identity))
    {
        Write-Verbose -Message ($script:localizedData.TestIdentityIsPresentOnPolicy -f "NULL", $Policy)

        if ($null -eq $userRights.Identity)
        {
            Write-Verbose -Message ($script:localizedData.NoIdentitiesFoundOnPolicy -f $Policy)
            return $true
        }
        else
        {
            Write-Verbose -Message ($script:localizedData.IdentityFoundExpectedNull -f $Policy)
            return $false
        }
    }

    Write-Verbose -Message ($script:localizedData.TestIdentityIsPresentOnPolicy -f $($Identity -join","), $Policy)

    foreach ($id in $Identity)
    {
        if ($userRights.Identity -notcontains $id)
        {
            Write-Verbose -Message ($script:localizedData.IdNotFoundOnPolicy -f $id, $Policy)
            return $false
        }      
    }    

    # If the code made it this far all identities have the desired user rights
    return $true
}

<#
    .SYNOPSIS
        Returns an object of the identities assigned to a user rights assignment
    .PARAMETER Policy
        Name of the policy to inspect
    .PARAMETER Areas
        Specifies the security areas to inspect. Possible values: "SECURITYPOLICY","GROUP_MGMT","USER_RIGHTS","REGKEYS","FILESTORE","SERVICES"
    .EXAMPLE
        Get-USRPolicy -Policy Create_a_token_object -Areas USER_RIGHTS
#>
function Get-USRPolicy
{
    [OutputType([PSObject])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateSet(
            "Create_a_token_object",
            "Access_this_computer_from_the_network",
            "Change_the_system_time",
            "Deny_log_on_as_a_batch_job",
            "Deny_log_on_through_Remote_Desktop_Services",
            "Create_global_objects",
            "Remove_computer_from_docking_station",
            "Deny_access_to_this_computer_from_the_network",
            "Act_as_part_of_the_operating_system",
            "Modify_firmware_environment_values",
            "Deny_log_on_locally",
            "Access_Credential_Manager_as_a_trusted_caller",
            "Restore_files_and_directories",
            "Change_the_time_zone",
            "Replace_a_process_level_token",
            "Manage_auditing_and_security_log",
            "Create_symbolic_links",
            "Modify_an_object_label",
            "Enable_computer_and_user_accounts_to_be_trusted_for_delegation",
            "Generate_security_audits",
            "Increase_a_process_working_set",
            "Take_ownership_of_files_or_other_objects",
            "Bypass_traverse_checking",
            "Log_on_as_a_service",
            "Shut_down_the_system",
            "Lock_pages_in_memory",
            "Impersonate_a_client_after_authentication",
            "Profile_system_performance",
            "Debug_programs",
            "Profile_single_process",
            "Allow_log_on_through_Remote_Desktop_Services",
            "Allow_log_on_locally",
            "Increase_scheduling_priority",
            "Synchronize_directory_service_data",
            "Add_workstations_to_domain",
            "Adjust_memory_quotas_for_a_process",
            "Obtain_an_impersonation_token_for_another_user_in_the_same_session",
            "Perform_volume_maintenance_tasks",
            "Load_and_unload_device_drivers",
            "Force_shutdown_from_a_remote_system",
            "Back_up_files_and_directories",
            "Create_a_pagefile",
            "Deny_log_on_as_a_service",
            "Log_on_as_a_batch_job",
            "Create_permanent_shared_objects"
        )]
        [System.String]
        $Policy,
        
        [parameter(Mandatory = $true)]
        [ValidateSet("SECURITYPOLICY","GROUP_MGMT","USER_RIGHTS","REGKEYS","FILESTORE","SERVICES")]
        [System.String]
        $Areas
    )

    $policyList = Get-AssignmentFriendlyNames
    $policyName = $policyList[$Policy]

    $currentUserRights = ([System.IO.Path]::GetTempFileName()).Replace('tmp','inf')    
    Write-Debug -Message ($localizedData.EchoDebugInf -f $currentUserRights)

    $secedit = secedit.exe /export /cfg $currentUserRights /areas $areas

    $userRights = (Get-UserRightsAssignment $currentUserRights).'Privilege Rights'    

    [PSObject]@{
        Policy = $policyName
        PolicyFriendlyName = $Policy
        Identity = $userRights[$policyName]
    }    
}

<#
    .SYNOPSIS
        Converts policy names that match the GUI to the abbreviated names used by secedit.exe 
#>
function Get-AssignmentFriendlyNames
{
    [OutputType([Hashtable])]
    [CmdletBinding()]
    Param ()
    
    Get-Content -Path $PSScriptRoot\UserRightsFriendlyNameConversions.psd1 -Raw | ConvertFrom-StringData
}

<#
    .SYNOPSIS 
        Creates Inf with desired configuration for a user rights assignment that is passed to secedit.exe
    .PARAMETER InfPolicy
        Name of user rights assignment policy
    .PARAMETER UserList
        List of users to be added to policy
    .PARAMETER FilePath
        Path to where the Inf will be created
    .EXAMPLE
        Out-UserRightsInf -InfPolicy SeTrustedCredManAccessPrivilege -UserList Contoso\User1 -FilePath C:\Scratch\Secedit.Inf
#>
function Out-UserRightsInf
{
    [CmdletBinding()]
    param
    (
        [System.String]
        $InfPolicy,

        [System.String]
        $UserList,

        [System.String]
        $FilePath
    )

    $infTemplate =@"
[Unicode]
Unicode=yes
[Privilege Rights]
$InfPolicy = $UserList
[Version]
signature="`$CHICAGO`$"
Revision=1
"@

    $null = Out-File -InputObject $infTemplate -FilePath $FilePath -Encoding unicode
}

Export-ModuleMember -Function *-TargetResource


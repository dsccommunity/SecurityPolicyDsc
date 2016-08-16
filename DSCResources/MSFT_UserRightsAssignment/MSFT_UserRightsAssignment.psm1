data LocalizedData
{
    ConvertFrom-StringData @'
IdentityIsNullRemovingAll=Identity is NULL. Removing all Identities from {0}
GrantingPolicyRightsToIds=Granting {0} rights to {1}
TaskSuccess=Task successfully completed
TaskSuccessFail=Task did not complete successfully
TestIdentityIsPresentOnPolicy=Testing {0} is present on policy {1}
NoIdentitiesFoundOnPolicy=No identities found on {0}
IdNNotFoundOnPolicy={0} not found on {1}
ErrorCantTranslateSID=Error processing {0}. {1}
EchoDebugInf=Temp inf {0}
EchoDebugTestInf=UserRightsInf {0}
'@

}

function Get-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [parameter(Mandatory = $true)]
        [ValidateSet("Create_a_token_object","Access_this_computer_from_the_network","Change_the_system_time","Deny_log_on_as_a_batch_job","Deny_log_on_through_Remote_Desktop_Services","Create_global_object","Remove_computer_from_docking_station","Deny_access_to_this_computer_form_the_network","Act_as_part_of_the_operating_system","Modify_firmware_environment_values","Deny_log_on_locally","Access_Credential_Manager_as_a_trusted_caller","Restore_files_and_directories","Change_the_time_zone","Replace_a_process_level_token","Manage_auditing_and_security_log","Create_symbolic_links","Modify_an_object_label","Enable_computer_and_user_accounts_to_be_trusted_for_delegation","Generate_security_audits","Increase_a_process_working_set","Take_ownership_of_files_or_other_objects","Bypass_traverse_checking","Log_on_as_a_service","Shut_down_the_system","Lock_pages_in_memory","Impersonate_a_client_after_authentication","Profile_system_performance","Debug_programs","Profile_single_process","Allow_log_on_through_Remote_Desktop_Services","Allow_log_on_locally","Increase_scheduling_priority","Synchronize_directory_service_data","Add_workstations_to_domain","Adjust_memory_quotas_for_a_process","Perform_volume_maintenance_tasks","Load_and_unload_device_drivers","Force_shutdown_from_a_remote_system","Back_up_files_and_directories","Create_a_pagefile","Deny_log_on_as_a_service","Log_on_as_a_batch_job","Create_permanent_shared_objects")]
        [System.String]
        $Policy,

        [parameter(Mandatory = $true)]
        [AllowNull()]
        [System.String[]]
        $Identity
    )
    
    $usrResult = Get-USRPolicy -Policy $Policy -Areas USER_RIGHTS

    If($($usrResult.Identity) -eq $null)
    {
        $ActualIdentity = 'NULL'
    }
    Else
    {
        $ActualIdentity = $usrResult.Identity
    }

    $returnValue = @{
        Policy         = $usrResult.PolicyFriendlyName
        Identity       = $Identity
        ActualIdentity = $ActualIdentity
    }

    $returnValue
}

function Set-TargetResource
{
    [CmdletBinding()]
    param
    (
        [parameter(Mandatory = $true)]
        [ValidateSet("Create_a_token_object","Access_this_computer_from_the_network","Change_the_system_time","Deny_log_on_as_a_batch_job","Deny_log_on_through_Remote_Desktop_Services","Create_global_object","Remove_computer_from_docking_station","Deny_access_to_this_computer_form_the_network","Act_as_part_of_the_operating_system","Modify_firmware_environment_values","Deny_log_on_locally","Access_Credential_Manager_as_a_trusted_caller","Restore_files_and_directories","Change_the_time_zone","Replace_a_process_level_token","Manage_auditing_and_security_log","Create_symbolic_links","Modify_an_object_label","Enable_computer_and_user_accounts_to_be_trusted_for_delegation","Generate_security_audits","Increase_a_process_working_set","Take_ownership_of_files_or_other_objects","Bypass_traverse_checking","Log_on_as_a_service","Shut_down_the_system","Lock_pages_in_memory","Impersonate_a_client_after_authentication","Profile_system_performance","Debug_programs","Profile_single_process","Allow_log_on_through_Remote_Desktop_Services","Allow_log_on_locally","Increase_scheduling_priority","Synchronize_directory_service_data","Add_workstations_to_domain","Adjust_memory_quotas_for_a_process","Perform_volume_maintenance_tasks","Load_and_unload_device_drivers","Force_shutdown_from_a_remote_system","Back_up_files_and_directories","Create_a_pagefile","Deny_log_on_as_a_service","Log_on_as_a_batch_job","Create_permanent_shared_objects")]
        [System.String]
        $Policy,

        [parameter(Mandatory = $true)]
        [AllowNull()]
        [System.String[]]
        $Identity
    )
    
    $policyList = Get-AssignmentFriendlyNames
    $policyName = $policyList[$Policy]
    $script:seceditOutput = "$env:TEMP\Secedit-OutPut.txt"
    $userRightsToAddInf = "$env:TEMP\userRightsToAdd.inf" 
    $idsToAdd = $Identity -join ","

    If($Identity -eq 'NULL')
    {
        Write-Verbose -Message ($LocalizedData.IdentityIsNullRemovingAll -f $Policy)
        $idsToAdd = $null
    }
    Else
    {
        Write-Verbose -Message ($LocalizedData.GrantingPolicyRightsToIds -f $Policy, $idsToAdd)
    }
       
    Out-UserRightsInf -InfPolicy $policyName -UserList $idsToAdd -FilePath $userRightsToAddInf
    Write-Debug -Message ($LocalizedData.EchoDebugInf -f $userRightsToAddInf)

    Invoke-Secedit -UserRightsToAddInf $userRightsToAddInf -SecEditOutput $seceditOutput

    #Verify secedit command was successful
    $testSuccuess = Test-TargetResource -Identity $Identity -Policy $Policy -Verbose:0

    If($testSuccuess -eq $true)
    {
        Write-Verbose -Message ($LocalizedData.TaskSuccess)
    }
    Else
    {
        $seceditResult = Get-Content $script:seceditOutput
        Write-Verbose -Message ($LocalizedData.TaskSuccessFail)
        throw "$($seceditResult[-1])"
    }
}

function Test-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [parameter(Mandatory = $true)]
        [ValidateSet("Create_a_token_object","Access_this_computer_from_the_network","Change_the_system_time","Deny_log_on_as_a_batch_job","Deny_log_on_through_Remote_Desktop_Services","Create_global_object","Remove_computer_from_docking_station","Deny_access_to_this_computer_form_the_network","Act_as_part_of_the_operating_system","Modify_firmware_environment_values","Deny_log_on_locally","Access_Credential_Manager_as_a_trusted_caller","Restore_files_and_directories","Change_the_time_zone","Replace_a_process_level_token","Manage_auditing_and_security_log","Create_symbolic_links","Modify_an_object_label","Enable_computer_and_user_accounts_to_be_trusted_for_delegation","Generate_security_audits","Increase_a_process_working_set","Take_ownership_of_files_or_other_objects","Bypass_traverse_checking","Log_on_as_a_service","Shut_down_the_system","Lock_pages_in_memory","Impersonate_a_client_after_authentication","Profile_system_performance","Debug_programs","Profile_single_process","Allow_log_on_through_Remote_Desktop_Services","Allow_log_on_locally","Increase_scheduling_priority","Synchronize_directory_service_data","Add_workstations_to_domain","Adjust_memory_quotas_for_a_process","Perform_volume_maintenance_tasks","Load_and_unload_device_drivers","Force_shutdown_from_a_remote_system","Back_up_files_and_directories","Create_a_pagefile","Deny_log_on_as_a_service","Log_on_as_a_batch_job","Create_permanent_shared_objects")]
        [System.String]
        $Policy,

        [parameter(Mandatory = $true)]
        [AllowNull()]
        [System.String[]]
        $Identity
    )
        
    $userRights = Get-USRPolicy -Policy $Policy -Areas USER_Rights

    Write-Verbose -Message ($LocalizedData.TestIdentityIsPresentOnPolicy -f $($Identity -join","), $Policy)

    If($Identity -eq 'null')
    {
        If($userRights.Identity -eq $null)
        {
            Write-Verbose -Message ($LocalizedData.NoIdentitiesFoundOnPolicy -f $Policy)
            return $true
        }
    }  
    Foreach($id in $Identity)
    {
        If($userRights.Identity -notcontains $id)
        {
            Write-Verbose -Message ($LocalizedData.IdNNotFoundOnPolicy -f $id, $Policy)
            return $false
        }      
    }    

    #If the code made it this far all identities have the desired user rights
    return $true
}

Export-ModuleMember -Function *-TargetResource

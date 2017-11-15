# SecurityPolicyDsc

A wrapper around secedit.exe to allow you to configure local security policies.  This resource requires a Windows OS with secedit.exe.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## How to Contribute

If you would like to contribute to this repository, please read the DSC Resource Kit [contributing guidelines](https://github.com/PowerShell/DscResource.Kit/blob/master/CONTRIBUTING.md).

## Resources

* **UserRightsAssignment**: Configures user rights assignments in local security policies.
* **SecurityTemplate**: Configures user rights assignments that are defined in an INF file.
* **AccountPolicy**: Configures the policies under the Account Policy node in local security policies.
* **SecurityOption**: Configures the policies under the Security Options node in local security policies.

## UserRightsAssignment

* **Policy**: The policy name of the user rights assignment to be configured.
* **Identity**: The identity of the user or group to be added or removed from the user rights assignment.

## SecurityTemplate

* **Path**: Path to an INF file that defines the desired security policies.

## AccountPolicy

* **Name**: A unique name of the AccountPolicy resource instance. This is not used during configuration but needed
to ensure the resource configuration is unique.
## For explanation of below settings, please consult Account Policies Reference.
* # https://technet.microsoft.com/en-us/library/jj852214(v=ws.11).aspx
* **Enforce_password_history**
* **Maximum_Password_Age**
* **Minimum_Password_Age**
* **Minimum_Password_Length**
* **Password_must_meet_complexity_requirements**
* **Store_passwords_using_reversible_encryption**
* **Account_lockout_duration**
* **Account_lockout_threshold**
* **Reset_account_lockout_counter_after**
* **Enforce_user_logon_restrictions**
* **Maximum_lifetime_for_service_ticket**
* **Maximum_lifetime_for_user_ticket**
* **Maximum_lifetime_for_user_ticket_renewal**
* **Maximum_tolerance_for_computer_clock_synchronization**

## SecurityOption

* **Name**: Name of security option configuration. This is not used during the configuration process but needed
to ensure the resource configuration instance is unique.

## For explanation of below settings, please consult Security Policy Reference.
* # https://technet.microsoft.com/en-us/library/jj852268(v=ws.11).aspx
* **Accounts_Administrator_account_status**
* **Accounts_Block_Microsoft_accounts**
* **Accounts_Guest_account_status**
* **Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only**
* **Accounts_Rename_administrator_account**
* **Accounts_Rename_guest_account**
* **Audit_Audit_the_access_of_global_system_objects**
* **Audit_Audit_the_use_of_Backup_and_Restore_privilege**
* **Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings**
* **Audit_Shut_down_system_immediately_if_unable_to_log_security_audits**
* **DCOM_Machine_Access_Restrictions_in_Security_Descriptor_Definition_Language_SDDL_syntax**
* **DCOM_Machine_Launch_Restrictions_in_Security_Descriptor_Definition_Language_SDDL_syntax**
* **Devices_Allow_undock_without_having_to_log_on**
* **Devices_Allowed_to_format_and_eject_removable_media**
* **Devices_Prevent_users_from_installing_printer_drivers**
* **Devices_Restrict_CD_ROM_access_to_locally_logged_on_user_only**
* **Devices_Restrict_floppy_access_to_locally_logged_on_user_only**
* **Domain_controller_Allow_server_operators_to_schedule_tasks**
* **Domain_controller_LDAP_server_signing_requirements**
* **Domain_controller_Refuse_machine_account_password_changes**
* **Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always**
* **Domain_member_Digitally_encrypt_secure_channel_data_when_possible**
* **Domain_member_Digitally_sign_secure_channel_data_when_possible**
* **Domain_member_Disable_machine_account_password_changes**
* **Domain_member_Maximum_machine_account_password_age**
* **Domain_member_Require_strong_Windows_2000_or_later_session_key**
* **Interactive_logon_Display_user_information_when_the_session_is_locked**
* **Interactive_logon_Do_not_display_last_user_name**
* **Interactive_logon_Do_not_require_CTRL_ALT_DEL**
* **Interactive_logon_Machine_account_lockout_threshold**
* **Interactive_logon_Machine_inactivity_limit**
* **Interactive_logon_Message_text_for_users_attempting_to_log_on**
* **Interactive_logon_Message_title_for_users_attempting_to_log_on**
* **Interactive_logon_Number_of_previous_logons_to_cache_in_case_domain_controller_is_not_available**
* **Interactive_logon_Prompt_user_to_change_password_before_expiration**
* **Interactive_logon_Require_Domain_Controller_authentication_to_unlock_workstation**
* **Interactive_logon_Require_smart_card**
* **Interactive_logon_Smart_card_removal_behavior**
* **Microsoft_network_client_Digitally_sign_communications_always**
* **Microsoft_network_client_Digitally_sign_communications_if_server_agrees**
* **Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers**
* **Microsoft_network_server_Amount_of_idle_time_required_before_suspending_session**
* **Microsoft_network_server_Attempt_S4U2Self_to_obtain_claim_information**
* **Microsoft_network_server_Digitally_sign_communications_always**
* **Microsoft_network_server_Digitally_sign_communications_if_client_agrees**
* **Microsoft_network_server_Disconnect_clients_when_logon_hours_expire**
* **Microsoft_network_server_Server_SPN_target_name_validation_level**
* **Network_access_Allow_anonymous_SID_Name_translation**
* **Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts**
* **Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares**
* **Network_access_Do_not_allow_storage_of_passwords_and_credentials_for_network_authentication**
* **Network_access_Let_Everyone_permissions_apply_to_anonymous_users**
* **Network_access_Named_Pipes_that_can_be_accessed_anonymously**
* **Network_access_Remotely_accessible_registry_paths**
* **Network_access_Remotely_accessible_registry_paths_and_subpaths**
* **Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares**
* **Network_access_Shares_that_can_be_accessed_anonymously**
* **Network_access_Sharing_and_security_model_for_local_accounts**
* **Network_security_Allow_Local_System_to_use_computer_identity_for_NTLM**
* **Network_security_Allow_LocalSystem_NULL_session_fallback**
* **Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities**
* **Network_security_Configure_encryption_types_allowed_for_Kerberos**
* **Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change**
* **Network_security_Force_logoff_when_logon_hours_expire**
* **Network_security_LAN_Manager_authentication_level**
* **Network_security_LDAP_client_signing_requirements**
* **Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients**
* **Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers**
* **Network_security_Restrict_NTLM_Add_remote_server_exceptions_for_NTLM_authentication**
* **Network_security_Restrict_NTLM_Add_server_exceptions_in_this_domain**
* **Network_Security_Restrict_NTLM_Incoming_NTLM_Traffic**
* **Network_Security_Restrict_NTLM_NTLM_authentication_in_this_domain**
* **Network_Security_Restrict_NTLM_Outgoing_NTLM_traffic_to_remote_servers**
* **Network_Security_Restrict_NTLM_Audit_Incoming_NTLM_Traffic**
* **Network_Security_Restrict_NTLM_Audit_NTLM_authentication_in_this_domain**
* **Recovery_console_Allow_automatic_administrative_logon**
* **Recovery_console_Allow_floppy_copy_and_access_to_all_drives_and_folders**
* **Shutdown_Allow_system_to_be_shut_down_without_having_to_log_on**
* **Shutdown_Clear_virtual_memory_pagefile**
* **System_cryptography_Force_strong_key_protection_for_user_keys_stored_on_the_computer**
* **System_cryptography_Use_FIPS_compliant_algorithms_for_encryption_hashing_and_signing**
* **System_objects_Require_case_insensitivity_for_non_Windows_subsystems**
* **System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links**
* **System_settings_Optional_subsystems**
* **System_settings_Use_Certificate_Rules_on_Windows_Executables_for_Software_Restriction_Policies**
* **User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account**
* **User_Account_Control_Allow_UIAccess_applications_to_prompt_for_elevation_without_using_the_secure_desktop**
* **User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode**
* **User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users**
* **User_Account_Control_Detect_application_installations_and_prompt_for_elevation**
* **User_Account_Control_Only_elevate_executables_that_are_signed_and_validated**
* **User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations**
* **User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode**
* **User_Account_Control_Switch_to_the_secure_desktop_when_prompting_for_elevation**
* **User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations**

## Versions

### Unreleased

### 2.1.0.0
* Updated SecurityOption to handle multi-line logon messages
* SecurityOption: Added logic and example to handle scenario when using Interactive_logon_Message_text_for_users_attempting_to_log_on

### 2.0.0.0
* Added SecurityOption and AccountPolicy
* Removed SecuritySetting

### 1.5.0.0
* Refactored user rights assignment to read and test easier. 

### 1.4.0.0

* Fixed bug in which friendly name translation may fail if user or group contains 'S-'.
* Fixed bug identified in issue 33 and 34 where Test-TargetResource would return false but was true

### 1.3.0.0

* Added functionality to support BaselineManagement Module.
* Updated UserRightsAssignment resource to respect dynamic local accounts.
* Added SecuritySetting resource to process additional INF settings.

### 1.2.0.0

* SecurityTemplate: Remove [ValidateNotNullOrEmpty()] attribute for IsSingleInstance parameter
* Fixed typos

### 1.1.0.0

* SecurityTemplate:
  * Made SecurityTemplate compatible with Nano Server
  * Fixed bug in which Path parameter failed when no User section was present

### 1.0.0.0

* Initial release with the following resources:
  * UserRightsAssignment
  * SecurityTemplate

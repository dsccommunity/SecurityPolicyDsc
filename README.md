# SecurityPolicyDsc

[![Build Status](https://dev.azure.com/dsccommunity/SecurityPolicyDsc/_apis/build/status/dsccommunity.SecurityPolicyDsc?branchName=master)](https://dev.azure.com/dsccommunity/SecurityPolicyDsc/_build/latest?definitionId={definitionId}&branchName=master)
![Azure DevOps coverage (branch)](https://img.shields.io/azure-devops/coverage/dsccommunity/SecurityPolicyDsc/{definitionId}/master)
[![Azure DevOps tests](https://img.shields.io/azure-devops/tests/dsccommunity/SecurityPolicyDsc/{definitionId}/master)](https://dsccommunity.visualstudio.com/SecurityPolicyDsc/_test/analytics?definitionId={definitionId}&contextType=build)
[![PowerShell Gallery (with prereleases)](https://img.shields.io/powershellgallery/vpre/SecurityPolicyDsc?label=SecurityPolicyDsc%20Preview)](https://www.powershellgallery.com/packages/SecurityPolicyDsc/)
[![PowerShell Gallery](https://img.shields.io/powershellgallery/v/SecurityPolicyDsc?label=SecurityPolicyDsc)](https://www.powershellgallery.com/packages/SecurityPolicyDsc/)

A wrapper around secedit.exe to allow you to configure local security policies.  This resource requires a Windows OS
with secedit.exe.

## Code of Conduct

This project has adopted this [Code of Conduct](CODE_OF_CONDUCT.md).

## Releases

For each merge to the branch `master` a preview release will be
deployed to [PowerShell Gallery](https://www.powershellgallery.com/).
Periodically a release version tag will be pushed which will deploy a
full release to [PowerShell Gallery](https://www.powershellgallery.com/).

## Contributing

Please check out common DSC Community [contributing guidelines](https://dsccommunity.org/guidelines/contributing).

## Change log

A full list of changes in each version can be found in the [change log](CHANGELOG.md).

## Resources

* **AccountPolicy**: Configures the policies under the Account Policy node in local security policies.
* **SecurityOption**: Configures the policies under the Security Options node in local security policies.
* **SecurityTemplate**: Configures user rights assignments that are defined in an INF file.
* **UserRightsAssignment**: Configures user rights assignments in local security policies.

### AccountPolicy

**For further explanation of these settings, please consult [Account Policies Reference](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/account-policies).**

| Parameter | Attribute | DataType | Description | Allowed Values |
| --- | --- | --- | --- | --- |
| **Name** | Key | String | A unique name of the AccountPolicy resource instance. This is not used during configuration. ||
| **Enforce_password_history** | Write | Uint32 | Specifies the number of unique new passwords that must be associated with a user account before an old password can be reused. A number from 0 through 24 can be specified ||
| **Maximum_Password_Age** | Write | Uint32 | Specifies the period of time (in days) that a password can be used before the system requires the user to change it. A number from 0 through 999 can be specified, with 0 meaning the password will never expire ||
| **Minimum_Password_Age** | Write | Uint32 | Specifies the period of time (in days) that a password must be used before the user can change it. A number from 0 to 998 can be specified ||
| **Minimum_Password_Length** | Write | Uint32 | Specifies the least number of characters that can make up a password for a user account. A number from 0 to 14 can be specified ||
| **Password_must_meet_ complexity_requirements** | Write | String | Specifies whether passwords must meet a series of guidelines that are considered important for a strong password |Enabled, Disabled|
| **Store_passwords_using_ reversible_encryption** | Write | String | Specifies whether passwords are stored in a way that is reversible to provides support for applications that use protocols that require the user's password for authentication  |Enabled, Disabled|
| **Account_lockout_duration** | Write | Uint32 | Specifies the number of minutes that a locked-out account remains locked out before automatically becoming unlocked. A number from 1 through 99,999 can be specified ||
| **Account_lockout_threshold** | Write | Uint32 | Specifies the number of failed sign-in attempts that will cause a user account to be locked ||
| **Reset_account_lockout_ counter_after** | Write | Uint32 | Specifies the number of minutes that must elapse from the time a user fails to log on before the failed logon attempt counter is reset to 0 ||

**Note:** The below settings pertain to Kerberos policies and must be set by a member in the domain admins group.

| Parameter | Attribute | DataType | Description | Allowed Values |
| --- | --- | --- | --- | --- |
| **Enforce_user_logon_ restrictions** | Write | String | Specifies whether the Kerberos V5 Key Distribution Center (KDC) validates every request for a session ticket against the user rights policy of the user account |Enabled, Disabled|
| **Maximum_lifetime_ for_service_ticket** | Write | Uint32 | Specifies the maximum number of minutes that a granted session ticket can be used to access a particular service. A number from 10 to the value of the 'Maximum lifetime for service ticket' policy setting can be specified ||
| **Maximum_lifetime_ for_user_ticket** | Write | Uint32 | Specifies the maximum amount of time (in hours) that a user's ticket-granting ticket can be used. A number from 0 to 99,999 can be specified ||
| **Maximum_lifetime_ for_user_ticket_ renewal** | Write | Uint32 | Specifies the period of time (in days) during which a user's ticket-granting ticket can be renewed. A number from 0 to 99,999 can be specified ||
| **Maximum_tolerance_ for_computer_clock_ synchronization** | Write | Uint32 | Specifies the maximum time difference (in minutes) that Kerberos V5 tolerates between the time on the client clock and the time on the domain controller that provides Kerberos authentication ||

### SecurityOption

**For further explanation of these settings, please consult [Security Options Reference](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/security-options).**

| Parameter | Attribute | DataType | Description | Allowed Values |
| --- | --- | --- | --- | --- |
| **Name** | Key | String | Describes the security option to be managed. This could be anything as long as it is unique ||
| **Accounts_Administrator_ account_status** | Write | String | Determines whether the local Administrator account is enabled or disabled |Enabled, Disabled|
| **Accounts_Block_ Microsoft_accounts** | Write | String | Prevents using the Settings app to add a Microsoft account for single sign-on (SSO) authentication for Microsoft services and some background services, or using a Microsoft account for single sign-on to other applications or services. |This policy is disabled, Users cant add Microsoft accounts, Users cant add or log on with Microsoft accounts|
| **Accounts_Guest_ account_status** | Write | String | Determines whether the Guest account is enabled or disabled |Enabled, Disabled|
| **Accounts_Limit_local_ account_use_of_blank_ passwords_to_console_ logon_only** | Write | String | Determines whether remote interactive logons by network services such as Remote Desktop Services, Telnet, and File Transfer Protocol (FTP) are allowed for local accounts that have blank passwords |Enabled, Disabled|
| **Accounts_Rename_ administrator_account** | Write | String | Determines whether a different account name is associated with the security identifier (SID) for the administrator account ||
| **Accounts_Rename_ guest_account** | Write | String | Determines whether a different account name is associated with the security identifier (SID) for the Guest account ||
| **Audit_Audit_the_ access_of_global_ system_objects** | Write | String | If you enable this policy setting, a default system access control list (SACL) is applied when the device creates system objects such as mutexes, events, semaphores, and MS-DOS devices. If you also enable the Audit object access audit setting, access to these system objects is audited |Enabled, Disabled|
| **Audit_Audit_the_ use_of_Backup_and_ Restore_privilege** | Write | String | Determines whether to audit the use of all user rights, including Backup and Restore, when the Audit privilege use policy setting is configured |Enabled, Disabled|
| **Audit_Force_audit_ policy_subcategory_ settings_Windows_ Vista_or_later_to_ override_audit_policy_ category_settings** | Write | String | Allows you to manage your audit policy in a more precise way by using audit policy subcategories |Enabled, Disabled|
| **Audit_Shut_down_ system_immediately_ if_unable_to_log_ security_audits** | Write | String | Determines whether the system shuts down if it is unable to log security events |Enabled, Disabled|
| **DCOM_Machine_Access_ Restrictions_in_ Security_Descriptor_ Definition_Language_ SDDL_syntax** | Write | String | Allows you to define additional computer-wide controls that govern access to all Distributed Component Object Model (DCOM) based applications on a device ||
| **DCOM_Machine_Launch_ Restrictions_in_ Security_Descriptor_ Definition_Language_ SDDL_syntax** | Write | String | Allows you to define additional computer-wide controls that govern access to all DCOM based applications on a device. However, the ACLs that are specified in this policy setting control local and remote COM launch requests (not access requests) on the device ||
| **Devices_Allow_undock_ without_having_to_ log_on** | Write | String | Enables or disables the ability of a user to remove a portable device from a docking station without logging on |Enabled, Disabled|
| **Devices_Allowed_to_ format_and_eject_ removable_media** | Write | String | Determines who is allowed to format and eject removable media. |Administrators, Administrators and Power Users, Administrators and Interactive Users|
| **Devices_Prevent_ users_from_installing_ printer_drivers** | Write | String | Determines who can install a printer driver as part of adding a network printer |Enabled, Disabled|
| **Devices_Restrict_ CD_ROM_access_to_ locally_logged_on_ user_only** | Write | String | Determines whether a CD is accessible to local and remote users simultaneously |Enabled, Disabled|
| **Devices_Restrict_ floppy_access_to_ locally_logged_on_ user_only** | Write | String | Determines whether removable floppy disks are accessible to local and remote users simultaneously |Enabled, Disabled|
| **Domain_controller_ Allow_server_operators_ to_schedule_tasks** | Write | String | Determines whether server operators can use the 'at' command to submit jobs.  |Enabled, Disabled|
| **Domain_controller_ LDAP_server_ signing_requirements** | Write | String | Determines whether the Lightweight Directory Access Protocol (LDAP) server requires LDAP clients to negotiate data signing |None, Require Signing|
| **Domain_controller_ Refuse_machine_ account_password_ changes** | Write | String | Enables or disables blocking a domain controller from accepting password change requests for machine accounts |Enabled, Disabled|
| **Domain_member_ Digitally_encrypt_ or_sign_secure_ channel_data_always** | Write | String | Determines whether all secure channel traffic that is initiated by the domain member must be signed or encrypted |Enabled, Disabled|
| **Domain_member_ Digitally_encrypt_ secure_channel_data_ when_possible** | Write | String | Determines whether all secure channel traffic that is initiated by the domain member must be encrypted |Enabled, Disabled|
| **Domain_member_ Digitally_sign_ secure_channel_data_ when_possible** | Write | String | Determines whether all secure channel traffic that is initiated by the domain member must be signed |Enabled, Disabled|
| **Domain_member_ Disable_machine_ account_password_ changes** | Write | String | Determines whether a domain member periodically changes its machine account password |Enabled, Disabled|
| **Domain_member_ Maximum_machine_ account_password_age** | Write | String | Determines when a domain member submits a password change ||
| **Domain_member_ Require_strong_ Windows_2000_or_ later_session_key** | Write | String | Determines whether a secure channel can be established with a domain controller that is not capable of encrypting secure channel traffic with a strong, 128-bit session key |Enabled, Disabled|
| **Interactive_logon_ Display_user_ information_when_ the_session_is_locked** | Write | String | Controls whether details such as email address or domain\username appear with the username on the sign-in screen |User displayname,  domain and user names, User display name only, Do not display user information|
| **Interactive_logon_ Do_not_display_ last_user_name** | Write | String | Determines whether the name of the last user to log on to the device is displayed on the Secure Desktop |Enabled, Disabled|
| **Interactive_logon_ Do_not_require_ CTRL_ALT_DEL** | Write | String | Determines whether pressing CTRL+ALT+DEL is required before a user can log on |Enabled, Disabled|
| **Interactive_logon_ Machine_account_ lockout_threshold** | Write | String | Allows you to set a threshold for the number of failed logon attempts that causes the device to be locked by using BitLocker ||
| **Interactive_logon_ Machine_inactivity_limit** | Write | String | Specifies the amount of inactive time before the user's session locks by invoking the screen saver ||
| **Interactive_logon_ Message_text_for_ users_attempting_ to_log_on** | Write | String | Specifies a text message to be displayed to users when they log on ||
| **Interactive_logon_ Message_title_for_ users_attempting_ to_log_on** | Write | String | Specifies a message title to be displayed to users when they log on ||
| **Interactive_logon_ Number_of_previous_ logons_to_cache_in_ case_domain_controller_  is_not_available** | Write | String | Determines whether a user can log on to a Windows domain by using cached account information ||
| **Interactive_logon_ Prompt_user_to_ change_password_ before_expiration** | Write | String | Determines how many days in advance users are warned that their passwords are about to expire ||
| **Interactive_logon_ Require_Domain_ Controller_ authentication_to_ unlock_workstation** | Write | String | Determines whether it is necessary to contact a domain controller to unlock a device |Enabled, Disabled|
| **Interactive_logon_ Require_smart_card** | Write | String | Requires users to log on to a device by using a smart card |Enabled, Disabled|
| **Interactive_logon_ Smart_card_removal_ behavior** | Write | String | Determines what happens when the smart card for a logged-on user is removed from the smart card reader |No Action, Lock workstation, Force logoff, Disconnect if a remote Remote Desktop Services session|
| **Microsoft_network_ client_Digitally_ sign_communications_ always** | Write | String | If this policy setting is enabled, SMBv2 clients will digitally sign all packets |Enabled, Disabled|
| **Microsoft_network_ client_Digitally_sign_ communications_if_ server_agrees** | Write | String | If this policy setting is enabled, SMBv2 clients will digitally sign all packets if the server agrees |Enabled, Disabled|
| **Microsoft_network_ client_Send_ unencrypted_ password_to_third_ party_SMB_servers** | Write | String | Allows or prevents the SMB redirector to send plaintext passwords to a non-Microsoft server service that does not support password encryption during authentication |Enabled, Disabled|
| **Microsoft_network_ server_Amount_ of_idle_time_ required_before_ suspending_session** | Write | String | Determines the amount of continuous idle time that must pass in an SMB session before the session is suspended due to inactivity ||
| **Microsoft_network_ server_Attempt_ S4U2Self_to_obtain_ claim_information** | Write | String | Specifies whether a Windows file server will attempt to use the Kerberos S4U2Self feature to obtain a claim-enabled access token for the client prinicipal if required. |Default, Enabled, Disabled|
| **Microsoft_network_ server_Digitally_ sign_communications_ always** | Write | String | Specifies whether an SMB server requires SMB network packets to be digitally signed |Enabled, Disabled|
| **Microsoft_network_ server_Digitally_ sign_communications_ if_client_agrees** | Write | String | Specifies whether an SMB server will negotaite to digitally sign SMB network packets with a client |Enabled, Disabled|
| **Microsoft_network_ server_Disconnect_ clients_when_logon_ hours_expire** | Write | String | Enables or disables the forced disconnection of users who are connected to the local device using SMB outside their user account's valid logon hours |Enabled, Disabled|
| **Microsoft_network_ server_Server_SPN_ target_name_ validation_level** | Write | String | Controls the level of validation that a server with shared folders or printers performs on the service principal name (SPN) that is provided by the client device when the client device establishes a session by using the Server Message Block (SMB) protocol |Off, Accept if provided by client, Required from client|
| **Network_access _Allow_anonymous_ SID_Name_translation** | Write | String | Enables or disables the ability of an anonymous user to request security identifier (SID) attributes for another user |Enabled, Disabled|
| **Network_access_ Do_not_allow_ anonymous_ enumeration_ of_SAM_accounts** | Write | String | Determines which additional permissions will be assigned for anonymous connections to the device. Windows allows anonymous users to perform certain activities, such as enumerating the names of domain accounts and network shares |Enabled, Disabled|
| **Network_access_ Do_not_allow_ anonymous_ enumeration_ of_SAM_accounts_ and_shares** | Write | String | Determines which additional permissions will be assigned for anonymous connections to the device. Windows allows anonymous users to perform certain activities, such as enumerating the names of domain accounts and network shares |Enabled, Disabled|
| **Network_access_ Do_not_allow_storage_ of_passwords_and_ credentials_for_ network_authentication** | Write | String | Determines whether Credential Manager saves passwords and credentials for later use when it gains domain authentication |Enabled, Disabled|
| **Network_access_ Let_Everyone_ permissions_apply_ to_anonymous_users** | Write | String | Determines what additional permissions are granted for anonymous connections to the device. If you enable this policy setting, anonymous users can enumerate the names of domain accounts and shared folders and perform certain other activities |Enabled, Disabled|
| **Network_access_ Named_Pipes_that_ can_be_accessed_ anonymously** | Write | String | Determines which communication sessions, or pipes, have attributes and permissions that allow anonymous access ||
| **Network_access_ Remotely_accessible_ registry_paths** | Write | String | Determines which registry paths are accessible when an application or process references the WinReg key to determine access permissions ||
| **Network_access_ Remotely_accessible_ registry_paths_and_ subpaths** | Write | String | Determines which registry paths and subpaths are accessible when an application or process references the WinReg key to determine access permissions ||
| **Network_access_ Restrict_anonymous_ access_to_Named_ Pipes_and_Shares** | Write | String | Enables or disables the restriction of anonymous access to only those shared folders and pipes that are named in the 'Network access: Named pipes that can be accessed anonymously' and 'Network access: Shares that can be accessed anonymously' settings |Enabled, Disabled|
| **Network_access_ Restrict_clients_ allowed_to_make_ remote_calls_to_SAM** | Write | String[] | The Permission and Identity required for restricted remote Sam access ||
| **Network_access_ Shares_that_can_be_ accessed_anonymously** | Write | String | Determines which shared folders can be accessed by anonymous users ||
| **Network_access_ Sharing_and_security_ model_for_local_ accounts** | Write | String | Determines how network logons that use local accounts are authenticated |Classic - Local users authenticate as themselves, Guest only - Local users authenticate as Guest|
| **Network_security_ Allow_Local_System_ to_use_computer_ identity_for_NTLM** | Write | String | Determines what identity to use for services running as Local System when NTLM is used |Enabled, Disabled|
| **Network_security_ Allow_LocalSystem_ NULL_session_fallback** | Write | String | Determines whether services that request the use of session security are allowed to perform signature or encryption functions with a well-known key for application compatibility |Enabled, Disabled|
| **Network_Security_ Allow_PKU2U_ authentication_requests_ to_this_computer_ to_use_online_identities** | Write | String | Determines whether authentication is allowed between two or more computers that have established a peer relationship through the use of online IDs |Enabled, Disabled|
| **Network_security_ Configure_encryption_ types_allowed_for_ Kerberos** | Write | String[] | Allows you to set the encryption types that the Kerberos protocol is allowed to use |DES_CBC_CRC, DES_CBC_MD5, RC4_HMAC_MD5, AES128_HMAC_SHA1, AES256_HMAC_SHA1, FUTURE|
| **Network_security_ Do_not_store_LAN_ Manager_hash_value_ on_next_password_ change** | Write | String | Determines whether LAN Manager is prevented from storing hash values for the new password the next time the password is changed |Enabled, Disabled|
| **Network_security_ Force_logoff_when_ logon_hours_expire** | Write | String | Determines whether to disconnect users who are connected to the local device using SMB outside their user account's valid logon hours |Enabled, Disabled|
| **Network_security_ LAN_Manager_ authentication_level** | Write | String | Determines which challenge or response authentication protocol is used for network logons |Send LM & NTLM responses, Send LM & NTLM - use NTLMv2 session security if negotiated, Send NTLM responses only, Send NTLMv2 responses only, Send NTLMv2 responses only. Refuse LM, Send NTLMv2 responses only. Refuse LM & NTLM|
| **Network_security_ LDAP_client_ signing_requirements** | Write | String | Determines the level of data signing that is requested on behalf of client devices that issue LDAP BIND requests |None, Negotiate Signing, Require Signing|
| **Network_security_ Minimum_session_ security_for_NTLM_ SSP_based_including_ secure_RPC_clients** | Write | String | Allows a client device to require the negotiation of 128-bit encryption or NTLMv2 session security |Require NTLMv2 session security, Require 128-bit encryption, Both options checked|
| **Network_security_ Minimum_session_ security_for_NTLM_ SSP_based_including_ secure_RPC_servers** | Write | String | Allows a client device to require the negotiation of 128-bit encryption or NTLMv2 session security |Require NTLMv2 session security, Require 128-bit encryption, Both options checked|
| **Network_security_ Restrict_NTLM_ Add_remote_server_ exceptions_for_ NTLM_authentication** | Write | String | Allows you to create an exception list of remote servers to which client devices are allowed to use NTLM authentication if the 'Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers' policy setting is configured ||
| **Network_security_ Restrict_NTLM_ Add_server_exceptions_ in_this_domain** | Write | String | Allows you to create an exception list of servers in this domain to which client device are allowed to use NTLM pass-through authentication if any of the deny options are set in the 'Network Security: Restrict NTLM: NTLM authentication in this domain' policy setting ||
 | **Network_Security_ Restrict_NTLM_ Incoming_NTLM_Traffic** | Write | String | Allows you to deny or allow incoming NTLM traffic from client computers, other member servers, or a domain controller |Allow all, Deny all domain accounts, Deny all accounts|
| **Network_Security_ Restrict_NTLM_ NTLM_authentication_ in_this_domain** | Write | String | Allows you to deny or allow NTLM authentication within a domain from this domain controller |Disable, Deny for domain accounts to domain servers, Deny for domain accounts, Deny for domain servers, Deny all|
| **Network_Security_ Restrict_NTLM_ Outgoing_NTLM_traffic_ to_remote_servers** | Write | String | Allows you to deny or audit outgoing NTLM traffic from a computer running Windows 7, Windows Server 2008, or later to any remote server running the Windows operating system |Allow all, Audit all, Deny all|
| **Network_Security_ Restrict_NTLM_ Audit_Incoming_ NTLM_Traffic** | Write | String | Allows you to audit incoming NTLM traffic |Disabled, Enable auditing for domain accounts, Enable auditing for all accounts|
| **Network_Security_ Restrict_NTLM_ Audit_NTLM_ authentication_ in_this_domain** | Write | String | Allows you to audit on the domain controller NTLM authentication in that domain |Disable, Enable for domain accounts to domain servers, Enable for domain accounts, Enable for domain servers, Enable all|
| **Recovery_console_ Allow_automatic_ administrative_logon** | Write | String | Determines whether the built-in Administrator account password must be provided before access to the Recovery Console on the device is granted |Enabled, Disabled|
| **Recovery_console_ Allow_floppy_ copy_and_access_ to_all_drives_and_ folders** | Write | String | Enables or disables the Recovery Console SET command |Enabled, Disabled|
| **Shutdown_Allow_ system_to_be_shut_ down_without_having_ to_log_on** | Write | String | Determines whether a device can be shut down without having to log on to Windows |Enabled, Disabled|
| **Shutdown_Clear_ virtual_memory_ pagefile** | Write | String | Determines whether the virtual memory paging file is cleared when the device is shut down |Enabled, Disabled|
| **System_cryptography_ Force_strong_ key_ protection_for_user_ keys_stored_on_the_ computer** | Write | String | Determines whether users can use private keys, such as their Secure/Multipurpose Internet Mail Extensions (S/MIME) key, without a password |User input is not required when new keys are stored and used, User is prompted when the key is first used, User must enter a password each time they use a key|
| **System_cryptography_ Use_FIPS_compliant_ algorithms_for_ encryption_hashing_ and_signing** | Write | String | Determines whether the TLS/SSL security provider supports only the FIPS-compliant strong cipher suite |Enabled, Disabled|
| **System_objects_ Require_case_ insensitivity_for_ non_Windows_ subsystems** | Write | String | Determines whether case insensitivity is enforced for all subsystems |Enabled, Disabled|
| **System_objects_ Strengthen_default_ permissions_of_ internal_system_objects_ eg_Symbolic_Links** | Write | String | Determines the strength of the default discretionary access control list (DACL) for objects |Enabled, Disabled|
| **System_settings_ Optional_subsystems** | Write | String | Determines which subsystems support your applications ||
| **System_settings_ Use_Certificate_ Rules_on_Windows_ Executables_for_ Software_Restriction_ Policies** | Write | String | Determines whether digital certificates are processed when software restriction policies are enabled and a user or process attempts to run software with an .exe file name extension |Enabled, Disabled|
| **User_Account_Control_ Admin_Approval_ Mode_for_the_Built_in_ Administrator_account** | Write | String | Determines the behavior of Admin Approval Mode for the built-in administrator account |Enabled, Disabled|
| **User_Account_Control_ Allow_UIAccess_ applications_to_prompt_ for_elevation_without_ using_the_secure_ desktop** | Write | String | Controls whether User Interface Accessibility (UIAccess or UIA) programs can automatically disable the secure desktop for elevation prompts that are used by a standard user |Enabled, Disabled|
| **User_Account_Control_ Behavior_of_the_ elevation_prompt_for_ administrators_ in_Admin_Approval_ Mode** | Write | String | Determines the behavior of the elevation prompt for accounts that have administrative credentials |Elevate without prompting, Prompt for credentials on the secure desktop, Prompt for consent on the secure desktop, Prompt for credentials, Prompt for consent, Prompt for consent for non-Windows binaries|
| **User_Account_Control_ Behavior_of_the_ elevation_prompt_for_ standard_users** | Write | String | Determines the behavior of the elevation prompt for standard users |Automatically deny elevation request, Prompt for credentials on the secure desktop, Prompt for credentials|
| **User_Account_Control_ Detect_application_ installations_and_ prompt_for_elevation** | Write | String | Determines the behavior of application installation detection for the entire system |Enabled, Disabled|
| **User_Account_Control_ Only_elevate_ executables_that_are_ signed_and_validated** | Write | String | Enforces public key infrastructure (PKI) signature checks on any interactive application that requests elevation of privilege |Enabled, Disabled|
| **User_Account_Control_ Only_elevate_UIAccess_ applications_that_are_ installed_in_secure_ locations** | Write | String | Enforces the requirement that apps that request running with a UIAccess integrity level (by means of a marking of UIAccess=true in their app manifest), must reside in a secure location on the file system |Enabled, Disabled|
| **User_Account_Control_ Run_all_administrators_ in_Admin_Approval_ Mode** | Write | String | Determines the behavior of all User Account Control (UAC) policies for the entire system |Enabled, Disabled|
| **User_Account_Control_ Switch_to_the_secure_ desktop_when_ prompting_for_elevation** | Write | String | Determines whether the elevation request prompts on the interactive user desktop or on the secure desktop |Enabled, Disabled|
| **User_Account_Control_ Virtualize_file_and_ registry_write_failures_ to_per_user_locations** | Write | String | Enables or disables the redirection of the write failures of earlier applications to defined locations in the registry and the file system |Enabled, Disabled|

### SecurityTemplate

| Parameter | Attribute | DataType | Description | Allowed Values |
| --- | --- | --- | --- | --- |
| **IsSingleInstance** | Key | String | Specifies the resource is a single instance, the value must be 'Yes' |Yes|
| **Path** | Required | String | The path to the desired security policy template (.inf) ||

### UserRightsAssignment

| Parameter | Attribute | DataType | Description | Allowed Values |
| --- | --- | --- | --- | --- |
| **Policy** | Key | String | The policy name of the user rights assignment to be configured. |Create_a_token_object, Access_this_computer_from_the_network, Change_the_system_time, Deny_log_on_as_a_batch_job, Deny_log_on_through_Remote_Desktop_Services, Create_global_objects, Remove_computer_from_docking_station, Deny_access_to_this_computer_from_the_network, Act_as_part_of_the_operating_system, Modify_firmware_environment_values, Deny_log_on_locally, Access_Credential_Manager_ as_a_trusted_caller, Restore_files_and_directories, Change_the_time_zone, Replace_a_process_level_token, Manage_auditing_and_security_log, Create_symbolic_links, Modify_an_object_label, Enable_computer_and_user_accounts_ to_be_trusted_for_delegation, Generate_security_audits, Increase_a_process_working_set, Take_ownership_of_files_ or_other_objects, Bypass_traverse_checking, Log_on_as_a_service, Shut_down_the_system, Lock_pages_in_memory, Impersonate_a_client_ after_authentication, Profile_system_performance, Debug_programs, Profile_single_process, Allow_log_on_through_ Remote_Desktop_Services, Allow_log_on_locally, Increase_scheduling_priority, Synchronize_directory_service_data, Add_workstations_to_domain, Adjust_memory_quotas_for_a_process, Obtain_an_impersonation_token_for_ another_user_in_the_same_session, Perform_volume_maintenance_tasks, Load_and_unload_device_drivers, Force_shutdown_from_a_remote_system, Back_up_files_and_directories, Create_a_pagefile, Deny_log_on_as_a_service, Log_on_as_a_batch_job, Create_permanent_shared_objects|
| **Identity** | Required | String[] | The identity of the user or group to be added or removed from the user rights assignment. ||
| **Force** | Write | Boolean | Specifies to explicitly assign only the identities defined ||
| **Ensure** | Write | String | Desired state of resource. |Present, Absent|

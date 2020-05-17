# Change log for SecurityPolicyDsc

## [Unreleased]

### Added

- SecurityPolicyDsc:
  - Added automatic release with a new CI pipeline
    [Issue #143](https://github.com/dsccommunity/SecurityPolicyDsc/issues/143).

### Changed

- SecurityPolicyDsc:
  - Resolved custom Script Analyzer rules that was added to the test framework.
  - Moved change log to CHANGELOG.md.
  - Added support for more SDDL SID constants
    [Issue #126](https://github.com/dsccommunity/SecurityPolicyDsc/issues/126).
    - Added functions to convert identity to and from SDDL SID constants.
    - Changed Format-RestrictedRemoteSAM to use new function to create strings with additional SDDL SID constants.
    - Changed ConvertTo-CimRestrictedRemoteSam to use new function to accept more possible SDDL SID constants.
    - Changed ConvertTo-CimRestrictedRemoteSam to skip CimInstance creation if no valid Identity was found.
  - Added schema descriptions for all properties and update README.
  - Added PowerShell Dsc Resource Help Files.
- AccountPolicy:
  - Improved and updated unit tests to Pester v4 format.

### Fixed

- AccountPolicy:
  - Fix applying Account_lockout_duration to zero
    [Issue #140](https://github.com/dsccommunity/SecurityPolicyDsc/issues/140).

## [2.10.0.0] - 2019-09-19

- Changes to SecurityPolicyDsc:
  - Opt-in to the following DSC Resource Common Meta Tests:
    - Common Tests - Validate Module Files
    - Common Tests - Validate Script Files
    - Common Tests - Validate Markdown Files
    - Common Tests - Required Script Analyzer Rules
    - Common Tests - Flagged Script Analyzer Rules
    - Common Tests - New Error-Level Script Analyzer Rules
    - Common Tests - Custom Script Analyzer Rules
    - Common Tests - Validate Markdown Links
    - Common Tests - Relative Path Length
    - Common Tests - Validate Example Files
    - Common Tests - Validate Example Files To Be Published
  - Fix keywords to lower-case to align with guideline.

## [2.9.0.0] - 2019-08-07

- Bug fix - Max password age fails when setting to 0.
  Fixes [Issue #121](https://github.com/dsccommunity/SecurityPolicyDsc/issues/121).
- Bug fix - Domain_controller_LDAP_server_signing_requirements - Require Signing.
  Fixes [Issue #122](https://github.com/dsccommunity/SecurityPolicyDsc/issues/122).
- Bug fix - Network_security_Restrict_NTLM security options correct parameter validation.
  This fix could impact your systems.

## [2.8.0.0] - 2019-04-03

- Bug fix - Issue 71 - Issue Added Validation Attributes to AccountPolicy & SecurityOption
- Bug fix - Network_security_Restrict_NTLM security option names now maps to correct keys.
  This fix could impact your systems.
- Updated LICENSE file to match the Microsoft Open Source Team standard.
  Fixes [Issue #108](https://github.com/dsccommunity/SecurityPolicyDsc/issues/108).
- Refactored the SID translation process to not throw a terminating error when called from Test-TargetResource
- Updated verbose message during the SID translation process to identify the policy where an orphaned SID exists
- Added the EType "FUTURE" to the security option 
  "Network\_security\_Configure\_encryption\_types\_allowed\_for\_Kerberos"
- Documentation update to include all valid settings for security options and account policies

## [2.7.0.0] - 2019-01-09

- Bug fix - Issue 83 - Network_access_Remotely_accessible_registry_paths_and_subpaths correctly applies multiple paths
- Update LICENSE file to match the Microsoft Open Source Team standard

## [2.6.0.0] - 2018-11-28

- Added SecurityOption - Network_access_Restrict_clients_allowed_to_make_remote_calls_to_SAM
- Bug fix - Issue 105 - Spelling error in SecurityOption 
  User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users
- Bug fix - Issue 90 - Corrected value for Microsoft_network_server_Server_SPN_target_name_validation_level policy

## [2.5.0.0] - 2018-09-05

- Added handler for null value in SecurityOption
- Moved the helper module out from DSCResource folder to the Modules folder.
- Fixed SecurityPolicyResourceHelper.Tests.ps1 so it possible to run the tests
  locally.
- Fixed minor typos.

## [2.4.0.0] - 2018-07-25

- Added additional error handling to ConvertTo-Sid helper function.

## [2.3.0.0] - 2018-06-13

- Updated documentation.
  - Add example of applying Kerberos policies
  - Added hyper links to readme

## [2.2.0.0] - 2017-12-20

- Fixed bug in UserRightAssignment where Get-DscConfiguration would fail if it returns $Identity as single string

## [2.1.0.0] - 2017-11-15

- Updated SecurityOption to handle multi-line logon messages
- SecurityOption: Added logic and example to handle scenario when using 
  Interactive_logon_Message_text_for_users_attempting_to_log_on

## [2.0.0.0] - 2017-10-05

- Added SecurityOption and AccountPolicy
- Removed SecuritySetting

## [1.5.0.0] - 2017-08-23

- Refactored user rights assignment to read and test easier.

## [1.4.0.0] - 2017-07-12

- Fixed bug in which friendly name translation may fail if user or group contains 'S-'.
- Fixed bug identified in issue 33 and 34 where Test-TargetResource would return false but was true

## [1.3.0.0] - 2017-06-01

- Added functionality to support BaselineManagement Module.
- Updated UserRightsAssignment resource to respect dynamic local accounts.
- Added SecuritySetting resource to process additional INF settings.

## [1.2.0.0] - 2017-03-08

- SecurityTemplate: Remove [ValidateNotNullOrEmpty()] attribute for IsSingleInstance parameter
- Fixed typos

## [1.1.0.0] - 2017-02-17

- SecurityTemplate:
  - Made SecurityTemplate compatible with Nano Server
  - Fixed bug in which Path parameter failed when no User section was present

## [1.0.0.0] - 2017-02-03

- Initial release with the following resources:
  - UserRightsAssignment
  - SecurityTemplate

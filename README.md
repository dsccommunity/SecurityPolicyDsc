# SecurityPolicyDsc

A wrapper around secedit.exe to allow you to configure local security policies.  This resource requires a Windows OS with secedit.exe.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## How to Contribute

If you would like to contribute to this repository, please read the DSC Resource Kit [contributing guidelines](https://github.com/PowerShell/DscResource.Kit/blob/master/CONTRIBUTING.md).

## Resources

* **UserRightsAssignment**: Configures user rights assignments in local security policies.
* **SecurityTemplate**: Configures user rights assignments that are defined in an INF file.
* **SecuritySetting**: Configures additional Security Settings typically associated with SecurityPolicy.

## UserRightsAssignment

* **Policy**: The policy name of the user rights assignment to be configured.
* **Identity**: The identity of the user or group to be added or removed from the user rights assignment.

## SecurityTemplate

* **Path**: Path to an INF file that defines the desired security policies.

## SecuritySetting

* **Name**: Name of Security Setting you are changing. Required to allow setting of any value without having to specify a hashtable or array while ensuring that resource has a KEY parameter.
## For explanation of below settings, please consult Security Policy Reference.
## https://technet.microsoft.com/en-us/library/dn452423(v=ws.11).aspx
* **ClearTextPassword**:
* **DependsOn**:
* **EnableAdminAccount**:
* **EnableGuestAccount**:
* **ForceLogoffWhenHourExpire**:
* **LockoutBadCount**:
* **LockoutDuration**:
* **LSAAnonymousNameLookup**:
* **MaxClockSkew**:
* **MaximumPasswordAge**:
* **MaxRenewAge**:
* **MaxServiceAge**:
* **MaxTicketAge**:
* **MinimumPasswordAge**:
* **MinimumPasswordLength**:
* **NewAdministratorName**:
* **NewGuestName**:
* **PasswordComplexity**:
* **PasswordHistorySize**:
* **PsDscRunAsCredential**:
* **ResetLockoutCount**:
* **TicketValidateClient**:

## Versions

### Unreleased

- Added functionality to support BaselineManagement Module.

### 1.3.0.0

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

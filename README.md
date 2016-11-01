# SeceditDSC
A wrapper around secedit.exe to allow you to confiugre local security policies.  This resouce requires a Windows OS with secedit.exe.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## How to Contribute
If you would like to contribute to this repository, please read the DSC Resource Kit [contributing guidelines](https://github.com/PowerShell/DscResource.Kit/blob/master/CONTRIBUTING.md).

## Resources
*  **UserRightsAssignment** configures user rights assignments in local security policies.
*  **SecInf** configures user rights assignments that are defined in an INF file

## UserRightsAssignment
* **Policy**: The policy name of the user right assignment to be configured.
* **Identity**: The identity of the user or group to be added or removed from the user right assignment.

## SecInf
* **PathToInf**: Path to Inf the defines the desired security policies.

## Versions

## Unreleased

1.0.0.0
* Initial release with the following resource:
 * UserRightsAssignment
 * SecInf

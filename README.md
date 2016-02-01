# xSecedit
A wrapper around secedit.exe to confiugre local security policies.

## Description
The xSecedit modules contains the xUserRightsAssignment DSC Resource.  This DSC Resource allows you to configure user rights assignment in Windows.

## Resources
* xUserRightsAssignment configures user rights assignments in local security policies.

## xUserRightsAssignment
* Policy: The policy name of the user right assignment to be configured.
* Identity: The identity of the user or group to be added or or removed from the user right assignment.
* Ensure: Specifies if the identities should be granted or removed from a user right assignment.

## Versions
1.0.0.0
* Initial release with the following resource:
 * xUserRightsAssignment
 

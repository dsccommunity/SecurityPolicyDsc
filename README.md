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
* **Force**: Specifies to explicitly assign only the identities defined.

## SecurityTemplate

* **Path**: Path to an INF file that defines the desired security policies.

## AccountPolicy

* **Name**: A unique name of the AccountPolicy resource instance. This is not used during configuration but needed
to ensure the resource configuration is unique.

## For explanation of below settings, please consult [Account Policies Reference](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/jj852214(v%3dws.11))

* **`[String]` Enforce\_password\_history** (Write) : Please see the link above for a full description. { Passwords Remembered }
* **`[String]` Maximum\_Password\_Age** (Write) : Please see the link above for a full description. { days }
* **`[String]` Minimum\_Password\_Age** (Write) : Please see the link above for a full description. { days }
* **`[String]` Minimum\_Password\_Length** (Write) : Please see the link above for a full description. { Character Count }
* **`[String]` Password\_must\_meet\_complexity\_requirements** (Write) : Please see the link above for a full description. { Disabled | Enabled }
* **`[String]` Store\_passwords\_using\_reversible\_encryption** (Write) : Please see the link above for a full description. { Disabled | Enabled }
* **`[String]` Account\_lockout\_duration** (Write) : Please see the link above for a full description. { minutes }
* **`[String]` Account\_lockout\_threshold** (Write) : Please see the link above for a full description. { invalid logon attempts}
* **`[String]` Reset\_account\_lockout\_counter\_after** (Write) : Please see the link above for a full description. { minutes }

(Note: The below settings pertain to Kerberos policies and must be set by a member in the domain admins group.

* **`[String]` Enforce\_user\_logon\_restrictions** (Write) : Please see the link above for a full description. { Disabled | Enabled }
* **`[String]` Maximum\_lifetime\_for\_service\_ticket** (Write) : Please see the link above for a full description. { minutes }
* **`[String]` Maximum\_lifetime\_for\_user\_ticket\_renewal** (Write) : Please see the link above for a full description. { days }
* **`[String]` Maximum\_lifetime\_for\_user\_ticket** (Write) : Please see the link above for a full description. { hours }
* **`[String]` Maximum\_tolerance\_for\_computer\_clock\_synchronization** (Write) : Please see the link above for a full description. { minutes }

## SecurityOption

* **Name**: Name of security option configuration. This is not used during the configuration process but needed
to ensure the resource configuration instance is unique.

## For explanation of below settings, please consult [Security Options Reference](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/jj852268(v%3dws.11))

* **`[String]` Accounts\_Administrator\_account\_status** (Write) : Please see the link above for a full description. { Disabled | Enabled }
* **`[String]` Accounts\_Block\_Microsoft\_accounts** (Write) : Please see the link above for a full description. { This policy is disabled | Users cant add Microsoft accounts | Users cant add or log on with Microsoft accounts }
* **`[String]` Accounts\_Guest\_account\_status** (Write) : Please see the link above for a full description. { Disabled | Enabled }
* **`[String]` Accounts\_Limit\_local\_account\_use\_of\_blank\_passwords\_to\_console\_logon\_only** (Write) : Please see the link above for a full description. { Disabled | Enabled }
* **`[String]` Accounts\_Rename\_administrator\_account** (Write) : Please see the link above for a full description. { String }
* **`[String]` Accounts\_Rename\_guest\_account** (Write) : Please see the link above for a full description. { String }
* **`[String]` Audit\_Audit\_the\_access\_of\_global\_system\_objects** (Write) : Please see the link above for a full description. { Disabled | Enabled }
* **`[String]` Audit\_Audit\_the\_use\_of\_Backup\_and\_Restore\_privilege** (Write) : Please see the link above for a full description. { Disabled | Enabled }
* **`[String]` Audit\_Force\_audit\_policy\_subcategory\_settings\_Windows\_Vista\_or\_later\_to\_override\_audit\_policy\_category\_settings** (Write) : Please see the link above for a full description. { Disabled | Enabled }
* **`[String]` Audit\_Shut\_down\_system\_immediately\_if\_unable\_to\_log\_security\_audits** (Write) : Please see the link above for a full description. { Disabled | Enabled }
* **`[String]` DCOM\_Machine\_Access\_Restrictions\_in\_Security\_Descriptor\_Definition\_Language\_SDDL\_syntax** (Write) : Please see the link above for a full description. { String }
* **`[String]` DCOM\_Machine\_Launch\_Restrictions\_in\_Security\_Descriptor\_Definition\_Language\_SDDL\_syntax** (Write) : Please see the link above for a full description. { String }
* **`[String]` Devices\_Allow\_undock\_without\_having\_to\_log\_on** (Write) : Please see the link above for a full description. { Disabled | Enabled }
* **`[String]` Devices\_Allowed\_to\_format\_and\_eject\_removable\_media** (Write) : Please see the link above for a full description. { Administrators and Interactive Users | Administrators | Administrators and Power Users }
* **`[String]` Devices\_Prevent\_users\_from\_installing\_printer\_drivers** (Write) : Please see the link above for a full description. { Disabled | Enabled }
* **`[String]` Devices\_Restrict\_CD\_ROM\_access\_to\_locally\_logged\_on\_user\_only** (Write) : Please see the link above for a full description. { Disabled | Enabled }
* **`[String]` Devices\_Restrict\_floppy\_access\_to\_locally\_logged\_on\_user\_only** (Write) : Please see the link above for a full description. { Disabled | Enabled }
* **`[String]` Domain\_controller\_Allow\_server\_operators\_to\_schedule\_tasks** (Write) : Please see the link above for a full description. { Disabled | Enabled }
* **`[String]` Domain\_controller\_LDAP\_server\_signing\_requirements** (Write) : Please see the link above for a full description. { None | Require Signing }
* **`[String]` Domain\_controller\_Refuse\_machine\_account\_password\_changes** (Write) : Please see the link above for a full description. { Disabled | Enabled }
* **`[String]` Domain\_member\_Digitally\_encrypt\_or\_sign\_secure\_channel\_data\_always** (Write) : Please see the link above for a full description. { Disabled | Enabled }
* **`[String]` Domain\_member\_Digitally\_encrypt\_secure\_channel\_data\_when\_possible** (Write) : Please see the link above for a full description. { Disabled | Enabled }
* **`[String]` Domain\_member\_Digitally\_sign\_secure\_channel\_data\_when\_possible** (Write) : Please see the link above for a full description. { Disabled | Enabled }
* **`[String]` Domain\_member\_Disable\_machine\_account\_password\_changes** (Write) : Please see the link above for a full description. { Disabled | Enabled }
* **`[String]` Domain\_member\_Maximum\_machine\_account\_password\_age** (Write) : Please see the link above for a full description. { String }
* **`[String]` Domain\_member\_Require\_strong\_Windows\_2000\_or\_later\_session\_key** (Write) : Please see the link above for a full description. { Disabled | Enabled }
* **`[String]` Interactive\_logon\_Display\_user\_information\_when\_the\_session\_is\_locked** (Write) : Please see the link above for a full description. { User displayname, domain and user names | Do not display user information | User display name only }
* **`[String]` Interactive\_logon\_Do\_not\_display\_last\_user\_name** (Write) : Please see the link above for a full description. { Disabled | Enabled }
* **`[String]` Interactive\_logon\_Do\_not\_require\_CTRL\_ALT\_DEL** (Write) : Please see the link above for a full description. { Disabled | Enabled }
* **`[String]` Interactive\_logon\_Machine\_account\_lockout\_threshold** (Write) : Please see the link above for a full description. { String }
* **`[String]` Interactive\_logon\_Machine\_inactivity\_limit** (Write) : Please see the link above for a full description. { String }
* **`[String]` Interactive\_logon\_Message\_text\_for\_users\_attempting\_to\_log\_on** (Write) : Please see the link above for a full description. { String }
* **`[String]` Interactive\_logon\_Message\_title\_for\_users\_attempting\_to\_log\_on** (Write) : Please see the link above for a full description. { String }
* **`[String]` Interactive\_logon\_Number\_of\_previous\_logons\_to\_cache\_in\_case\_domain\_controller\_is\_not\_available** (Write) : Please see the link above for a full description. { String }
* **`[String]` Interactive\_logon\_Prompt\_user\_to\_change\_password\_before\_expiration** (Write) : Please see the link above for a full description. { String }
* **`[String]` Interactive\_logon\_Require\_Domain\_Controller\_authentication\_to\_unlock\_workstation** (Write) : Please see the link above for a full description. { Disabled | Enabled }
* **`[String]` Interactive\_logon\_Require\_smart\_card** (Write) : Please see the link above for a full description. { Disabled | Enabled }
* **`[String]` Interactive\_logon\_Smart\_card\_removal\_behavior** (Write) : Please see the link above for a full description. { Lock workstation | Force logoff | Disconnect if a remote Remote Desktop Services session | No Action }
* **`[String]` Microsoft\_network\_client\_Digitally\_sign\_communications\_always** (Write) : Please see the link above for a full description. { Disabled | Enabled }
* **`[String]` Microsoft\_network\_client\_Digitally\_sign\_communications\_if\_server\_agrees** (Write) : Please see the link above for a full description. { Disabled | Enabled }
* **`[String]` Microsoft\_network\_client\_Send\_unencrypted\_password\_to\_third\_party\_SMB\_servers** (Write) : Please see the link above for a full description. { Disabled | Enabled }
* **`[String]` Microsoft\_network\_server\_Amount\_of\_idle\_time\_required\_before\_suspending\_session** (Write) : Please see the link above for a full description. { String }
* **`[String]` Microsoft\_network\_server\_Attempt\_S4U2Self\_to\_obtain\_claim\_information** (Write) : Please see the link above for a full description. { Default | Disabled | Enabled }
* **`[String]` Microsoft\_network\_server\_Digitally\_sign\_communications\_always** (Write) : Please see the link above for a full description. { Disabled | Enabled }
* **`[String]` Microsoft\_network\_server\_Digitally\_sign\_communications\_if\_client\_agrees** (Write) : Please see the link above for a full description. { Disabled | Enabled }
* **`[String]` Microsoft\_network\_server\_Disconnect\_clients\_when\_logon\_hours\_expire** (Write) : Please see the link above for a full description. { Disabled | Enabled }
* **`[String]` Microsoft\_network\_server\_Server\_SPN\_target\_name\_validation\_level** (Write) : Please see the link above for a full description. { Off | Required from client | Accept if provided by the client }
* **`[String]` Network\_access\_Allow\_anonymous\_SID\_Name\_translation** (Write) : Please see the link above for a full description. { Disabled | Enabled }
* **`[String]` Network\_access\_Do\_not\_allow\_anonymous\_enumeration\_of\_SAM\_accounts** (Write) : Please see the link above for a full description. { Disabled | Enabled }
* **`[String]` Network\_access\_Do\_not\_allow\_anonymous\_enumeration\_of\_SAM\_accounts\_and\_shares** (Write) : Please see the link above for a full description. { Disabled | Enabled }
* **`[String]` Network\_access\_Do\_not\_allow\_storage\_of\_passwords\_and\_credentials\_for\_network\_authentication** (Write) : Please see the link above for a full description. { Disabled | Enabled }
* **`[String]` Network\_access\_Let\_Everyone\_permissions\_apply\_to\_anonymous\_users** (Write) : Please see the link above for a full description. { Disabled | Enabled }
* **`[String]` Network\_access\_Named\_Pipes\_that\_can\_be\_accessed\_anonymously** (Write) : Please see the link above for a full description. { String }
* **`[String]` Network\_access\_Remotely\_accessible\_registry\_paths** (Write) : Please see the link above for a full description. { String }
* **`[String]` Network\_access\_Remotely\_accessible\_registry\_paths\_and\_subpaths** (Write) : Please see the link above for a full description. { String }
* **`[String]` Network\_access\_Restrict\_anonymous\_access\_to\_Named\_Pipes\_and\_Shares** (Write) : Please see the link above for a full description. { Disabled | Enabled }
* **`[String[]]` Network\_access\_Restrict\_clients\_allowed\_to\_make\_remote\_calls\_to\_SAM** (Write) : Please see the link above for a full description.
* **`[String]` Network\_access\_Shares\_that\_can\_be\_accessed\_anonymously** (Write) : Please see the link above for a full description. { String }
* **`[String]` Network\_access\_Sharing\_and\_security\_model\_for\_local\_accounts** (Write) : Please see the link above for a full description. { Guest only - Local users authenticate as Guest | Classic - Local users authenticate as themselves }
* **`[String]` Network\_security\_Allow\_Local\_System\_to\_use\_computer\_identity\_for\_NTLM** (Write) : Please see the link above for a full description. { Disabled | Enabled }
* **`[String]` Network\_security\_Allow\_LocalSystem\_NULL\_session\_fallback** (Write) : Please see the link above for a full description. { Disabled | Enabled }
* **`[String]` Network\_Security\_Allow\_PKU2U\_authentication\_requests\_to\_this\_computer\_to\_use\_online\_identities** (Write) : Please see the link above for a full description. { Disabled | Enabled }
* **`[String]` Network\_security\_Configure\_encryption\_types\_allowed\_for\_Kerberos** (Write) : Please see the link above for a full description. { AES256\_HMAC\_SHA1 | DES\_CBC\_MD5 | FUTURE | AES128\_HMAC\_SHA1 | DES\_CBC\_CRC | RC4\_HMAC\_MD5 | FUTURE }
* **`[String]` Network\_security\_Do\_not\_store\_LAN\_Manager\_hash\_value\_on\_next\_password\_change** (Write) : Please see the link above for a full description. { Disabled | Enabled }
* **`[String]` Network\_security\_Force\_logoff\_when\_logon\_hours\_expire** (Write) : Please see the link above for a full description. { Disabled | Enabled }
* **`[String]` Network\_security\_LAN\_Manager\_authentication\_level** (Write) : Please see the link above for a full description. { Send NTLMv2 responses only. Refuse LM | Send NTLMv2 responses only. Refuse LM & NTLM | Send LM & NTLM responses | Send LM & NTLM - use NTLMv2 session security if negotiated | Send NTLMv2 responses only | Send NTLM responses only }
* **`[String]` Network\_security\_LDAP\_client\_signing\_requirements** (Write) : Please see the link above for a full description. { Negotiate Signing | Require Signing | None }
* **`[String]` Network\_security\_Minimum\_session\_security\_for\_NTLM\_SSP\_based\_including\_secure\_RPC\_clients** (Write) : Please see the link above for a full description. { Require 128-bit encryption | Require NTLMv2 session security | Both options checked }
* **`[String]` Network\_security\_Minimum\_session\_security\_for\_NTLM\_SSP\_based\_including\_secure\_RPC\_servers** (Write) : Please see the link above for a full description. { Require 128-bit encryption | Require NTLMv2 session security | Both options checked }
* **`[String]` Network\_security\_Restrict\_NTLM\_Add\_remote\_server\_exceptions\_for\_NTLM\_authentication** (Write) : Please see the link above for a full description. { String }
* **`[String]` Network\_security\_Restrict\_NTLM\_Add\_server\_exceptions\_in\_this\_domain** (Write) : Please see the link above for a full description. { String }
* **`[String]` Network\_Security\_Restrict\_NTLM\_Audit\_Incoming\_NTLM\_Traffic** (Write) : Please see the link above for a full description. { Deny all | Deny for domain accounts | Deny for domain servers | Disable | Deny for domain accounts to domain servers }
* **`[String]` Network\_Security\_Restrict\_NTLM\_Audit\_NTLM\_authentication\_in\_this\_domain** (Write) : Please see the link above for a full description. { Deny all | Audit all | Allow all }
* **`[String]` Network\_Security\_Restrict\_NTLM\_Incoming\_NTLM\_Traffic** (Write) : Please see the link above for a full description. { Enable auditing for domain accounts | Enable auditing for all accounts | Disabled }
* **`[String]` Network\_Security\_Restrict\_NTLM\_NTLM\_authentication\_in\_this\_domain** (Write) : Please see the link above for a full description. { Enable all | Enable for domain accounts | Enable for domain servers | Disable | Enable for domain accounts to domain servers }
* **`[String]` Network\_Security\_Restrict\_NTLM\_Outgoing\_NTLM\_traffic\_to\_remote\_servers** (Write) : Please see the link above for a full description. { Deny all accounts | Deny all domain accounts | Allow all }
* **`[String]` Recovery\_console\_Allow\_automatic\_administrative\_logon** (Write) : Please see the link above for a full description. { Disabled | Enabled }
* **`[String]` Recovery\_console\_Allow\_floppy\_copy\_and\_access\_to\_all\_drives\_and\_folders** (Write) : Please see the link above for a full description. { Disabled | Enabled }
* **`[String]` Shutdown\_Allow\_system\_to\_be\_shut\_down\_without\_having\_to\_log\_on** (Write) : Please see the link above for a full description. { Disabled | Enabled }
* **`[String]` Shutdown\_Clear\_virtual\_memory\_pagefile** (Write) : Please see the link above for a full description. { Disabled | Enabled }
* **`[String]` System\_cryptography\_Force\_strong\_key\_protection\_for\_user\_keys\_stored\_on\_the\_computer** (Write) : Please see the link above for a full description. { User input is not required when new keys are stored and used | User must enter a password each time they use a key | User is prompted when the key is first used }
* **`[String]` System\_cryptography\_Use\_FIPS\_compliant\_algorithms\_for\_encryption\_hashing\_and\_signing** (Write) : Please see the link above for a full description. { Disabled | Enabled }
* **`[String]` System\_objects\_Require\_case\_insensitivity\_for\_non\_Windows\_subsystems** (Write) : Please see the link above for a full description. { Disabled | Enabled }
* **`[String]` System\_objects\_Strengthen\_default\_permissions\_of\_internal\_system\_objects\_eg\_Symbolic\_Links** (Write) : Please see the link above for a full description. { Disabled | Enabled }
* **`[String]` System\_settings\_Optional\_subsystems** (Write) : Please see the link above for a full description. { String }
* **`[String]` System\_settings\_Use\_Certificate\_Rules\_on\_Windows\_Executables\_for\_Software\_Restriction\_Policies** (Write) : Please see the link above for a full description. { Disabled | Enabled }
* **`[String]` User\_Account\_Control\_Admin\_Approval\_Mode\_for\_the\_Built\_in\_Administrator\_account** (Write) : Please see the link above for a full description. { Disabled | Enabled }
* **`[String]` User\_Account\_Control\_Allow\_UIAccess\_applications\_to\_prompt\_for\_elevation\_without\_using\_the\_secure\_desktop** (Write) : Please see the link above for a full description. { Disabled | Enabled }
* **`[String]` User\_Account\_Control\_Behavior\_of\_the\_elevation\_prompt\_for\_administrators\_in\_Admin\_Approval\_Mode** (Write) : Please see the link above for a full description. { Elevate without prompting | Prompt for consent | Prompt for credentials on the secure desktop | Prompt for credentials | Prompt for consent for non-Windows binaries | Prompt for consent on the secure desktop }
* **`[String]` User\_Account\_Control\_Behavior\_of\_the\_elevation\_prompt\_for\_standard\_users** (Write) : Please see the link above for a full description. { Prompt for crendentials | Prompt for credentials on the secure desktop | Automatically deny elevation request }
* **`[String]` User\_Account\_Control\_Detect\_application\_installations\_and\_prompt\_for\_elevation** (Write) : Please see the link above for a full description. { Disabled | Enabled }
* **`[String]` User\_Account\_Control\_Only\_elevate\_executables\_that\_are\_signed\_and\_validated** (Write) : Please see the link above for a full description. { Disabled | Enabled }
* **`[String]` User\_Account\_Control\_Only\_elevate\_UIAccess\_applications\_that\_are\_installed\_in\_secure\_locations** (Write) : Please see the link above for a full description. { Disabled | Enabled }
* **`[String]` User\_Account\_Control\_Run\_all\_administrators\_in\_Admin\_Approval\_Mode** (Write) : Please see the link above for a full description. { Disabled | Enabled }
* **`[String]` User\_Account\_Control\_Switch\_to\_the\_secure\_desktop\_when\_prompting\_for\_elevation** (Write) : Please see the link above for a full description. { Disabled | Enabled }
* **`[String]` User\_Account\_Control\_Virtualize\_file\_and\_registry\_write\_failures\_to\_per\_user\_locations** (Write) : Please see the link above for a full description. { Disabled | Enabled }

## Branches

### master

[![Build status](https://ci.appveyor.com/api/projects/status/github/PowerShell/SecurityPolicyDsc?branch=master?svg=true)](https://ci.appveyor.com/project/PowerShell/SecurityPolicyDsc/branch/master)
[![codecov](https://codecov.io/gh/PowerShell/SecurityPolicyDsc/branch/master/graph/badge.svg)](https://codecov.io/gh/PowerShell/SecurityPolicyDsc/branch/master)

This is the branch containing the latest release -
no contributions should be made directly to this branch.

### dev

[![Build status](https://ci.appveyor.com/api/projects/status/github/PowerShell/SecurityPolicyDsc?branch=dev?svg=true)](https://ci.appveyor.com/project/PowerShell/SecurityPolicyDsc/branch/dev)
[![codecov](https://codecov.io/gh/PowerShell/SecurityPolicyDsc/branch/dev/graph/badge.svg)](https://codecov.io/gh/PowerShell/SecurityPolicyDsc/branch/dev)

This is the development branch
to which contributions should be proposed by contributors as pull requests.
This development branch will periodically be merged to the master branch,
and be released to [PowerShell Gallery](https://www.powershellgallery.com/).

## Change log

A full list of changes in each version can be found in the [change log](CHANGELOG.md).

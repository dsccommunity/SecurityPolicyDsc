
<#
    The SecurityPolicyDsc module is a wrapped around secedit.exe, which takes an INI file containing security policies with the associated settings.
    The INI file used by secedit.exe must have the desired policy value on one line.  In a scenario in which a multi-line message is used a new line is 
    represented with a comma.  If commas are used in the message and a new line is not intended they must be surrounded my double quotes.
    The example below will result in the following logon message:

    Line 1 - Message for line 1.
    Line 2 - Message for line 2, words, separated, with, commas.
    Line 3 - Message for line 3.
#>
configuration LogonMessage
{
    Import-DscResource -ModuleName SecurityPolicyDsc
    $message = 'Line 1 - Message for line 1.,Line 2 - Message for line 2"," words"," separated"," with"," commas.,Line 3 - Message for line 3.'

    node localhost
    {
        SecurityOption LogonMessage
        {
            Name = "Message Test"
            Interactive_logon_Message_text_for_users_attempting_to_log_on = $message
        }
    }
}

LogonMessage -OutputPath c:\dscMessage
Start-DscConfiguration -Path c:\dscMessage -Wait -Force -Verbose

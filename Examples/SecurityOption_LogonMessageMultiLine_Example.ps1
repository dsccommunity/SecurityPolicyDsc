
configuration LogonMessage
{
    Import-DscResource -ModuleName SecurityPolicyDsc
    $multiLineMessage = @'
    Line 1 - Message for line 1.
    Line 2 - Message for line 2, words, seperated, with, commas.
    Line 3 - Message for line 3.
'@

    node localhost
    {
        SecurityOption LogonMessage
        {
            Name = "Message Test"
            Interactive_logon_Message_text_for_users_attempting_to_log_on = $multiLineMessage
        }
    }
}

LogonMessage -OutputPath c:\dscMessage
Start-DscConfiguration -Path c:\dscMessage -Wait -Force -Verbose

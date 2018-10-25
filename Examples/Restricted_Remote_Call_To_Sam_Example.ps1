configuration RemoteSam
{
    Import-DscResource -ModuleName SecurityPolicyDsc

    node localhost
    {
        SecurityOption RemoteSam
        {
            Name = 'test'
            Network_access_Restrict_clients_allowed_to_make_remote_calls_to_SAM = @(
                MSFT_RestrictedRemoteSamSecurityDescriptor
                {
                    Permission = 'Deny'
                    Identity   = 'ServerAdmin'
                }
                 MSFT_RestrictedRemoteSamSecurityDescriptor
                {
                    Permission = 'Allow'
                    Identity   = 'Administrators'
                }
            )

            Network_access_Allow_anonymous_SID_Name_translation = 'Disabled'
        }
    }
}

RemoteSam -OutputPath c:\dscSam
Start-DscConfiguration -Path c:\dscSam -Verbose -Wait -Force

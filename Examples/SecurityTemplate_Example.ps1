Configuration CompareInfs
{
    Import-DscResource -ModuleName SecurityPolicyDsc

    node localhost
    {
        SecurityTemplate TrustedCredentialAccess
        {
            Path = "C:\scratch\UserRights.inf"
        }
    }
}

CompareInfs -OutputPath C:\DSC
Start-DscConfiguration -Path C:\DSC -Wait -Verbose -Force

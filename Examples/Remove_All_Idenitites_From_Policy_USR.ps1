Configuration UserRights
{
    Import-DscResource -ModuleName SeceditDSC

    Node localhost
    {
        UserRightsAssignment RemoveIdsFromSeTrustedCredManAccessPrivilege
        {
            #When Identity is NULL and Ensure is Present all identities will be removed from the policy
            Policy = "Access_Credential_Manager_as_a_trusted_caller"
            Identity = 'NULL'
        }
    }
}

UserRights -OutputPath c:\dsc

Start-DscConfiguration -Path c:\dsc -Verbose -Wait -Force 
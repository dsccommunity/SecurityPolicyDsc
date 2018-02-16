Configuration UserRights
{
    Import-DscResource -ModuleName SecurityPolicyDsc

    Node localhost
    {
        # Assign shutdown privileges to only Builtin\Administrators
        UserRightsAssignment AssignShutdownPrivilegesToAdmins
        {
            Policy   = "Shut_down_the_system"
            Identity = "Builtin\Administrators"
            Force    = $true
        }

        # Assign access from the network privileges to "contoso\TestUser1" and "contoso\TestUser2" without overwritting existing identities
        UserRightsAssignment AccessComputerFromNetwork
        {
            Policy   = "Access_this_computer_from_the_network"
            Identity = "contoso\TestUser1","contoso\TestUser2"
        }
    }
}

UserRights -OutputPath c:\dsc

Start-DscConfiguration -Path c:\dsc -Verbose -Wait -Force

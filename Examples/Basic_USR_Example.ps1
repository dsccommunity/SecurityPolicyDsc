Configuration UserRights
{
    Import-DscResource -ModuleName xSecedit

    Node localhost
    {
        xUserRightsAssignment AssignShutdownPrivlegesToAdmins
        {
            #Assign shutdown privileges to only Builtin\Administrators
            Policy = "Shut_down_the_system"
            Identity = "Builtin\Administrators"
            Ensure = "Present"
        }

        #Assign access from the network privileges to "whlab\TestUser1" and "whlab\TestUser2"
        xUserRightsAssignment AccessComputerFromNetwork
        {
            Policy = "Access_this_computer_from_the_network"
            Identity = "whlab\TestUser1","whlab\TestUser2"
            Ensure = "Present"
        }

        #Removes trusted caller privileges to Credential Manger for "whlab\testuser1"
        xUserRightsAssignment AccessCredManager
        {
            Policy = "Access_Credential_Manager_as_a_trusted_caller"
            Identity = "whlab\testuser2"
            Ensure = "Absent"
        }
    }

}

UserRights -OutputPath c:\dsc

Start-DscConfiguration -Path c:\dsc -Verbose -Wait -Force 
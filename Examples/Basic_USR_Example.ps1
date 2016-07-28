Configuration UserRights
{
    Import-DscResource -ModuleName xSecedit

    Node localhost
    {
		#Assign shutdown privileges to only Builtin\Administrators
        xUserRightsAssignment AssignShutdownPrivlegesToAdmins
        {            
            Policy = "Shut_down_the_system"
            Identity = "Builtin\Administrators"
        }

        #Assign access from the network privileges to "whlab\TestUser1" and "whlab\TestUser2"
        xUserRightsAssignment AccessComputerFromNetwork
        {
            Policy = "Access_this_computer_from_the_network"
            Identity = "contoso\TestUser1","contoso\TestUser2"
        }
    }

}

UserRights -OutputPath c:\dsc

Start-DscConfiguration -Path c:\dsc -Verbose -Wait -Force 
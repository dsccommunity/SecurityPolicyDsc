<<<<<<< HEAD
﻿Configuration CompareInfs
=======
Configuration CompareInfs
>>>>>>> dev
{
    Import-DscResource -ModuleName SeceditDsc

    node localhost
    {
        SecInf TrustedCredentialAccess
        {
            PathToInf = "C:\scratch\UserRights.inf"
        }
    }
}

CompareInfs -OutputPath C:\DSC
Start-DscConfiguration -Path C:\DSC -Wait -Verbose -Force

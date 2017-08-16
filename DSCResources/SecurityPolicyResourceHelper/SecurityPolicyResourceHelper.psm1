
<#
    .SYNOPSIS
        Retrieves the localized string data based on the machine's culture.
        Falls back to en-US strings if the machine's culture is not supported.

    .PARAMETER ResourceName
        The name of the resource as it appears before '.strings.psd1' of the localized string file.
        For example:
            AuditPolicySubcategory: MSFT_AuditPolicySubcategory
            AuditPolicyOption: MSFT_AuditPolicyOption
#>
function Get-LocalizedData
{
    [OutputType([String])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true, ParameterSetName = 'resource')]
        [ValidateNotNullOrEmpty()]
        [String]
        $ResourceName,

        [Parameter(Mandatory = $true, ParameterSetName = 'helper')]
        [ValidateNotNullOrEmpty()]
        [String]
        $HelperName
    )

    # With the helper module just update the name and path variables as if it were a resource. 
    if ($PSCmdlet.ParameterSetName -eq 'helper')
    {
        $resourceDirectory = $PSScriptRoot
        $ResourceName = $HelperName
    }
    else 
    {
        # Step up one additional level to build the correct path to the resource culture.
        $resourceDirectory = Join-Path -Path ( Split-Path $PSScriptRoot -Parent ) `
                                       -ChildPath $ResourceName
    }

    $localizedStringFileLocation = Join-Path -Path $resourceDirectory -ChildPath $PSUICulture

    if (-not (Test-Path -Path $localizedStringFileLocation))
    {
        # Fallback to en-US

        $localizedStringFileLocation = Join-Path -Path $resourceDirectory -ChildPath 'en-US'
    }

    Import-LocalizedData `
        -BindingVariable 'localizedData' `
        -FileName "$ResourceName.strings.psd1" `
        -BaseDirectory $localizedStringFileLocation

    return $localizedData
}

<#
    .SYNOPSIS
        Wrapper around secedit.exe used to make changes
    .PARAMETER UserRightsToAddInf
        Path to an INF file with desired user rights assignment policy configuration
    .PARAMETER SeceditOutput
        Path to secedit log file output
    .EXAMPLE
        Invoke-Secedit -UserRightsToAddInf C:\secedit.inf -SeceditOutput C:\seceditLog.txt
#>
function Invoke-Secedit
{
    [OutputType([void])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $UserRightsToAddInf,

        [Parameter(Mandatory = $true)]
        [System.String]
        $SeceditOutput,

        [Parameter()]
        [System.Management.Automation.SwitchParameter]
        $OverWrite
    )

    $script:localizedData = Get-LocalizedData -HelperName 'SecurityPolicyResourceHelper'

    $tempDB = "$env:TEMP\DscSecedit.sdb"
    $arguments = "/configure /db $tempDB /cfg $userRightsToAddInf"

    if ($OverWrite)
    {
        $arguments = $arguments + " /overwrite /quiet"
    }

    Start-Process -FilePath secedit.exe -ArgumentList $arguments -RedirectStandardOutput $seceditOutput -NoNewWindow -Wait
}

function Get-SecurityPolicy
{
    [OutputType([Hashtable])]
    [CmdletBinding()]
    param
    (       
        [Parameter(Mandatory = $true)]
        [ValidateSet("SECURITYPOLICY","GROUP_MGMT","USER_RIGHTS","REGKEYS","FILESTORE","SERVICES")]
        [System.String]
        $Area
    )

    $currentSecurityPolicyFilePath = Join-Path -Path $env:temp -ChildPath 'SecurityPolicy.inf'   
    Write-Debug -Message ($localizedData.EchoDebugInf -f $currentSecurityPolicyFilePath)

    secedit.exe /export /cfg $currentSecurityPolicyFilePath /areas $Area | Out-Null
    
    $policyConfiguration = @{}
    switch -regex -file $currentSecurityPolicyFilePath
    {
        "^\[(.+)\]" # Section
        {
            $section = $matches[1]
            $policyConfiguration[$section] = @{}
            $CommentCount = 0
        }
        "^(;.*)$" # Comment
        {
            $value = $matches[1]
            $commentCount = $commentCount + 1
            $name = "Comment" + $commentCount
            $policyConfiguration[$section][$name] = $value
        } 
        "(.+?)\s*=(.*)" # Key
        {
            $name,$value =  $matches[1..2] -replace "\*"
            $policyConfiguration[$section][$name] = @(ConvertTo-LocalFriendlyName $($value -split ','))
        }
    }

    Switch($Area)
    {
        "USER_RIGHTS" 
        {
            $returnValue = $policyConfiguration.'Privilege Rights'
            continue
        }
    }

    # Cleanup the temp file
    Remove-Item -Path $currentSecurityPolicyFilePath

    return $returnValue
}

<#
    .SYNOPSIS
        Parses an INF file produced by 'secedit.exe /export' and returns an object of identites assigned to a user rights assignment policy
    .PARAMETER FilePath
        Path to an INF file
    .EXAMPLE
        Get-UserRightsAssignment -FilePath C:\seceditOutput.inf
#>
function Get-UserRightsAssignment
{
    [OutputType([Hashtable])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $FilePath
    )

    $policyConfiguration = @{}
    switch -regex -file $FilePath
    {
        "^\[(.+)\]" # Section
        {
            $section = $matches[1]
            $policyConfiguration[$section] = @{}
            $CommentCount = 0
        }
        "^(;.*)$" # Comment
        {
            $value = $matches[1]
            $commentCount = $commentCount + 1
            $name = "Comment" + $commentCount
            $policyConfiguration[$section][$name] = $value
        } 
        "(.+?)\s*=(.*)" # Key
        {
            $name,$value =  $matches[1..2] -replace "\*"
            $policyConfiguration[$section][$name] = @(ConvertTo-LocalFriendlyName $($value -split ','))
        }
    }
    return $policyConfiguration
}

<#
    .SYNOPSIS
        Converts SID to a friendly name
    .PARAMETER SID
        SID of an identity being converted
    .EXAMPLE
        ConvertTo-LocalFriendlyName -SID 'S-1-5-21-3623811015-3361044348-30300820-1013'
#>
function ConvertTo-LocalFriendlyName
{
    [OutputType([String[]])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String[]]
        $SID
    )
    
    $localizedData = Get-LocalizedData -HelperName 'SecurityPolicyResourceHelper'

    $friendlyNames = [String[]]@()

    foreach ($id in $SID)
    {
        $id = $id.Trim()
        
        Write-Verbose  "Received Identity ($id)"
        if ($null -ne $id -and $id -match '^(S-[0-9-]{3,})')
        {
            try
            {
                Write-Verbose -Message ($localizedData:TranslateID -f $id)
                $securityIdentifier = [System.Security.Principal.SecurityIdentifier]($id)
                $user = $securityIdentifier.Translate([System.Security.Principal.NTAccount])
                $friendlyNames += $user.value
                Write-Verbose -Message ($localizedData:IdTranslatesTo -f $id,$user.Value)
            }
            catch
            {
                Write-Warning -Message ($localizedData.ErrorCantTranslateSID -f $id, $($_.Exception.Message) )
            }
        }
        elseIf ( ( Get-DomainRole ) -eq 'DomainController')
        {
            $friendlyNames += "$($env:USERDOMAIN + '\' + $($id))"
        }
        elseIf ($id -notmatch '^S-')
        {
            $friendlyNames += "$($id)"
        }
    }

    return $friendlyNames
}

<#
    .SYNOPSIS
        Converts int value from the Win32_ComputerSystem class into its text equivalent
#>
function Get-DomainRole
{
    [OutputType([String])]
    [CmdletBinding()]
    param()

    $domainRoleInt = (Get-CimInstance -ClassName Win32_ComputerSystem).DomainRole

    if ($domainRoleInt -eq 0)
    {
        $domainRole = 'StandaloneWorkstation'
    }
    elseif($domainRoleInt -eq 1)
    {
        $domainRole = 'MemberWorkstation'
    }
    elseif($domainRoleInt -eq 2)
    {
        $domainRole = 'StandaloneServer'
    }
    elseif($domainRoleInt -eq 3)
    {
        $domainRole = 'MemberServer'
    }
    else
    {
        $domainRole = 'DomainController'
    }

    return $domainRole
}


<#
    .SYNOPSIS
        Tests if the provided Identity is null
    .PARAMETER Identity
        The identity string to test
#>
function Test-IdentityIsNull
{
    [OutputType([bool])]
    [CmdletBinding()]
    param
    ( 
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()] 
        [AllowEmptyString()]
        [AllowNull()]
        [System.String[]]
        $Identity
    )

    if ( $null -eq $Identity -or [System.String]::IsNullOrWhiteSpace($Identity) )
    {
        return $true
    }
    else 
    {
        return $false
    }
}

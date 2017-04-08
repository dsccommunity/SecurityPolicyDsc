function IsNumeric
{
    param($Value)
    try
    {
        0 + $Value | Out-Null
        $IsNumeric = 1
    }
    catch
    {
        $IsNumeric = 0
    }

    if($IsNumeric){
        $IsNumeric = 1
        if($Boolean) { $Isnumeric = $True }
    }else{
        $IsNumeric = 0
        if($Boolean) { $IsNumeric = $False }
    }
    return $IsNumeric
}

$headerSettings = @{
MinimumPasswordAge = "System Access"
MaximumPasswordAge = "System Access"
MinimumPasswordLength = "System Access"
PasswordComplexity = "System Access"
PasswordHistorySize = "System Access"
LockoutBadCount = "System Access"
ForceLogoffWhenHourExpire = "System Access"
NewAdministratorName = "System Access"
NewGuestName = "System Access"
ClearTextPassword = "System Access"
LSAAnonymousNameLookup = "System Access"
EnableAdminAccount = "System Access"
EnableGuestAccount = "System Access"
ResetLockoutCount = "System Access"
LockoutDuration = "System Access"
MaxServiceAge = "Keberos Policy"
MaxTicketAge = "Kerberos Policy"
MaxRenewAge = "Kerberos Policy"
MaxClockSkew = "Kerberos Policy"
TicketValidateClient = "Kerberos Policy"
}

function Get-IniContent 
{
??? [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName=$true)]
        [ValidateScript({Test-Path $_})]
        [string]$Path
    )

    $ini = @{}
??? switch -regex -file $Path
??? {
??????? ?^\[(.+)\]? # Section
??????? {
??????????? $section = $matches[1]
??????????? $ini[$section] = @{}
??????????? $CommentCount = 0
??????? }
??????? ?^(;.*)$? # Comment
??????? {
??????????? $value = $matches[1]
??????????? $CommentCount = $CommentCount + 1
??????????? $name = ?Comment? + $CommentCount
??????????? $ini[$section][$name] = $value
            continue
??????? } 
??????? ?(.+?)\s*=(.*)? # Key
??????? {
??????????? $name,$value = $matches[1..2]
??????????? $ini[$section][$name] = $value
            # Need to replace double quotes with `"
            continue
??????? }
        "\`"(.*)`",(.*)$" 
        { 
            $name, $value = $matches[1..2]
            $ini[$section][$name] = $value
            continue
        }
??? }
??? return $ini
}

function Get-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidateSet("MinimumPasswordAge","MaximumPasswordAge","MinimumPasswordLength","PasswordComplexity","PasswordHistorySize","LockoutBadCount","ForceLogoffWhenHourExpire","NewAdministratorName","NewGuestName","ClearTextPassword","LSAAnonymousNameLookup","EnableAdminAccount","EnableGuestAccount","ResetLockoutCount","LockoutDuration","MaxServiceAge","MaxTicketAge","MaxRenewAge","MaxClockSkew","TicketValidateClient")]
        [string]$Name
    )
    
    $file = "C:\Windows\security\database\temppol.inf"
    Write-Verbose "Creating temp Security Settings file: $file"
    
    $outHash = @{}

    $ps = new-object System.Diagnostics.Process
    $ps.StartInfo.Filename = "secedit.exe"
    $ps.StartInfo.Arguments = " /export /cfg $file /areas securitypolicy"
    $ps.StartInfo.RedirectStandardOutput = $True
    $ps.StartInfo.UseShellExecute = $false
    [void]$ps.start() | Out-Null
    [void]$ps.WaitForExit('10') | Out-Null
    [string] $process = $ps.StandardOutput.ReadToEnd();

    $ini = Get-IniContent -Path $file
    Remove-Item $file -Force
    
    return $ini
}

# This will run ONLY if Test-TargetResource is $false
function Set-TargetResource
{
    [CmdletBinding()]
    [OutputType([boolean])]
    param
    (
        [ValidateRange(-1, 999)]
        [ValidateScript({$_ -ne 0})]
        [int]$MinimumPasswordAge,
        
        [ValidateRange(0,999)]
        [int]$MaximumPasswordAge,

        [int]$MinimumPasswordLength,
        [intl]$PasswordComplexity,
        [int]$PasswordHistorySize,
    
        [int]$LockoutBadCount,
        [intl]$ForceLogoffWhenHourExpire,
        [String]$NewAdministratorName,
        [String]$NewGuestName,
        [int]$ClearTextPassword,
        [int]$LSAAnonymousNameLookup,
        [int]$EnableAdminAccount,
        [int]$EnableGuestAccount,

        [int]$ResetLockoutCount,
        
        [ValidateRange(-1, 99999)]
        [ValidateScript({$_ -ne 0})]
        [int]$LockoutDuration,
        
        [ValidateScript({$_ -ge 10})]
        [int]$MaxServiceAge,
        
        [ValidateRange(0,99999)]
        [int]$MaxTicketAge,
        
        [ValidateRange(0,99999)]
        [int]$MaxRenewAge,
        
        [ValidateRange(0,99999)]
        [int]$MaxClockSkew,
        [intl]$TicketValidateClient,

        [ValidateSet("Present","Absent")]
        [string]$Ensure = "Present",

        [Parameter(Mandatory=$true)]
        [ValidateSet("MinimumPasswordAge","MaximumPasswordAge","MinimumPasswordLength","PasswordComplexity","PasswordHistorySize","LockoutBadCount","ForceLogoffWhenHourExpire","NewAdministratorName","NewGuestName","ClearTextPassword","LSAAnonymousNameLookup","EnableAdminAccount","EnableGuestAccount","ResetLockoutCount","LockoutDuration","MaxServiceAge","MaxTicketAge","MaxRenewAge","MaxClockSkew","TicketValidateClient")]
        [string]$Name
    )
    
    if (@($PSBoundParameters.Keys.Where({$_ -notin "Name", "Ensure"})).Count -eq 0)
    {
        Write-Error "No Values Specified!"
    }

    # Find out what sections we are setting.
    $PSBoundParameters.Remove("Ensure")
    $PSBoundParameters.Remove("Name")
    $headers = ($PSBoundParameters.GetEnumerator() | ForEach-Object { $headerSettings[$_.Key] } | Group-Object).Name
    
    $INI = Get-TargetResource -Name $Name
    $tmpFile = "C:\Windows\security\database\tmppol.inf"
    $new_secdb = "C:\Windows\security\database\tmpsecedit.sdb"
    
    Write-Verbose "Ceating tmp Security Settings file: $tmpfile"
    Write-Verbose "Ceating tmp Security Settings file: $file"
    foreach ($header in $headers)
    {
        foreach ($KeyPair in $PSBoundParameters.GetEnumerator())
        {
            try
            {
                $INI[$header][$KeyPair.Key] = $KeyPair.Value
            }
            catch
            {
                Write-Error "Unable to set $($KeyPair.Key) to $($KeyPair.Value)."
                continue
            }
        }    
    }

    if (Test-Path $tmpFile)
    {
        Remove-Item $tmpFile -Force
    }
        
    "[Unicode]" | Out-File $tmpfile
    "Unicode=yes" | Out-File $tmpfile -Append
    foreach ($headers in $headers)
    {
        "[$header]" | Out-File $tmpfile -Append
    
        foreach ($KeyPair in $INI[$header].GetEnumerator())
        {
            $Value = 1
            if ([int]::TryParse($KeyPair.value, [ref]$Value))
            {
                "$($KeyPair.Name) = $Value" | Out-File $tmpFile -Append
            }
            else
            {
                "$($KeyPair.Name) = `"$($KeyPair.Value)`"" | Out-File $tmpFile -Append 
            }
        }
    }
    
    "[Version]" | Out-File $tmpfile -Append
    "signature=`"`$CHICAGO`$`"" | Out-File $tmpfile -Append
    "Revision=1" | Out-File $tmpfile -Append
    
    $ps = new-object System.Diagnostics.Process
    $ps.StartInfo.Filename = "secedit.exe"
    $ps.StartInfo.Arguments = " /configure /db $new_secdb /cfg $tmpfile /overwrite /quiet"
    $ps.StartInfo.RedirectStandardOutput = $True
    $ps.StartInfo.UseShellExecute = $false
    [void]$ps.start() | Out-Null
    [void]$ps.WaitForExit('10') | Out-Null
    [string] $process = $ps.StandardOutput.ReadToEnd();
    
    Remove-Item $tmpfile -Force
}

function Test-TargetResource
{
    [CmdletBinding()]
    [OutputType([Boolean])]
    param
    (
        [ValidateRange(-1, 999)]
        [ValidateScript({$_ -ne 0})]
        [int]$MinimumPasswordAge,
        
        [ValidateRange(0,999)]
        [int]$MaximumPasswordAge,

        [int]$MinimumPasswordLength,
        [intl]$PasswordComplexity,
        [int]$PasswordHistorySize,
    
        [int]$LockoutBadCount,
        [intl]$ForceLogoffWhenHourExpire,
        [String]$NewAdministratorName,
        [String]$NewGuestName,
        [int]$ClearTextPassword,
        [int]$LSAAnonymousNameLookup,
        [int]$EnableAdminAccount,
        [int]$EnableGuestAccount,

        [int]$ResetLockoutCount,
        
        [ValidateRange(-1, 99999)]
        [ValidateScript({$_ -ne 0})]
        [int]$LockoutDuration,
        
        [ValidateScript({$_ -ge 10})]
        [int]$MaxServiceAge,
        
        [ValidateRange(0,99999)]
        [int]$MaxTicketAge,
        
        [ValidateRange(0,99999)]
        [int]$MaxRenewAge,
        
        [ValidateRange(0,99999)]
        [int]$MaxClockSkew,
        [intl]$TicketValidateClient,

        [ValidateSet("Present","Absent")]
        [string]$Ensure = "Present",
        
        [Parameter(Mandatory=$true)]
        [ValidateSet("MinimumPasswordAge","MaximumPasswordAge","MinimumPasswordLength","PasswordComplexity","PasswordHistorySize","LockoutBadCount","ForceLogoffWhenHourExpire","NewAdministratorName","NewGuestName","ClearTextPassword","LSAAnonymousNameLookup","EnableAdminAccount","EnableGuestAccount","ResetLockoutCount","LockoutDuration","MaxServiceAge","MaxTicketAge","MaxRenewAge","MaxClockSkew","TicketValidateClient")]
        [string]$Name
    )

    if (@($PSBoundParameters.Keys.Where({$_ -notin "Name", "Ensure"})).Count -eq 0)
    {
        Write-Error "No Values Specified!"
        return $false
    }
        
    # Find out what sections we are setting.
    $PSBoundParameters.Remove("Ensure") | Out-Null
    $PSBoundParameters.Remove("Name") | Out-Null
    $headers = ($PSBoundParameters.GetEnumerator() | ForEach-Object { $headerSettings[$_.Key] } | Group-Object).Name
    
    $INI = Get-TargetResource -Name $Name

    $returnValue = $true
    foreach ($header in $headers)
    {
        foreach ($KeyPair in ($PSBoundParameters.GetEnumerator() | Where-Object {$headerSettings[$_.Key] -eq $header}))
        {
            if ($INI.ContainsKey($header))
            {
                if ($INI[$header][$KeyPair.Key] -eq $KeyPair.Value)
                {
                    Write-Verbose "Tested $($KeyPair.Key) expecting $($KeyPair.Value): SUCCESS!"
                }
                else
                {
                    Write-Verbose "Tested $($KeyPair.Key) expecting $($KeyPair.Value): FAILURE!"
                    $returnValue = $false
                }
            }
            else
            {
                Write-Verbose "Could not find section ($header)"
                $returnValue = $false
            }
        }
    }
    
    return $returnValue
}


Export-ModuleMember -Function *-TargetResource

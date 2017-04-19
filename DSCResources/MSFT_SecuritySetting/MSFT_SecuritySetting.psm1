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
  [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName=$true)]
        [ValidateScript({Test-Path $_})]
        [System.String]$Path
    )

    $ini = @{}
    switch -regex -file $Path
    {
        "^\[(.+)\]"  # Section
        {
            $section = $matches[1]
            $ini[$section] = @{}
            $CommentCount = 0
        }
        "^(;.*)$"  # Comment
        {
            $value = $matches[1]
            $CommentCount = $CommentCount + 1
            $name = "Comment" + $CommentCount
            $ini[$section][$name] = $value
            continue
        } 
        "(.+ )\s*=(.*)"  # Key
        {
            $name,$value = $matches[1..2]
            $ini[$section][$name] = $value
            # Need to replace double quotes with `"
            continue
        }
        "\`"(.*)`",(.*)$" 
        { 
            $name, $value = $matches[1..2]
            $ini[$section][$name] = $value
            continue
        }
    }
    return $ini
}

function Get-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidateSet("MinimumPasswordAge","MaximumPasswordAge","MinimumPasswordLength","PasswordComplexity","PasswordHistorySize","LockoutBadCount","ForceLogoffWhenHourExpire","NewAdministratorName","NewGuestName","ClearTextPassword","LSAAnonymousNameLookup","EnableAdminAccount","EnableGuestAccount","ResetLockoutCount","LockoutDuration","MaxServiceAge","MaxTicketAge","MaxRenewAge","MaxClockSkew","TicketValidateClient")]
        [System.String]$Name
    )
    
    $file = Join-Path -Path $env:SystemRoot -ChildPath "\security\database\temppol.inf"
    Write-Verbose "Creating temp Security Settings file: $file"
    
    $outHash = @{}

    $PowerShellProcess = new-object System.Diagnostics.Process
    $PowerShellProcess.StartInfo.Filename = "secedit.exe"
    $PowerShellProcess.StartInfo.Arguments = " /export /cfg $file /areas securitypolicy"
    $PowerShellProcess.StartInfo.RedirectStandardOutput = $True
    $PowerShellProcess.StartInfo.UseShellExecute = $false
    $PowerShellProcess.start() | Out-Null
    $PowerShellProcess.WaitForExit('10') | Out-Null
    [System.String] $process = $PowerShellProcess.StandardOutput.ReadToEnd();

    $ini = Get-IniContent -Path $file
    Remove-Item $file -Force
    
    return $ini
}

function Set-TargetResource
{
    [CmdletBinding()]
    param
    (
        [Parameter()]
        [ValidateRange(-1, 999)]
        [ValidateScript({$_ -ne 0})]
        [System.Int16]$MinimumPasswordAge,
        
        [Parameter()]
        [ValidateRange(0,999)]
        [System.UInt16]$MaximumPasswordAge,

        [Parameter()]
        [System.UInt16]$MinimumPasswordLength,
        
        [Parameter()]
        [System.UInt16]$PasswordComplexity,
        
        [Parameter()]
        [System.UInt16]$PasswordHistorySize,
        
        [Parameter()]
        [System.UInt16]$LockoutBadCount,
        
        [Parameter()]
        [System.UInt16]$ForceLogoffWhenHourExpire,
        
        [Parameter()]
        [System.String]$NewAdministratorName,
        
        [Parameter()]
        [System.String]$NewGuestName,

        [Parameter()]
        [System.UInt16]$ClearTextPassword,
        
        [Parameter()]
        [System.UInt16]$LSAAnonymousNameLookup,
        
        [Parameter()]
        [System.UInt16]$EnableAdminAccount,
        
        [Parameter()]
        [System.UInt16]$EnableGuestAccount,

        [Parameter()]
        [System.Int16]$ResetLockoutCount,
        
        [Parameter()]
        [ValidateRange(-1, 99999)]
        [ValidateScript({$_ -ne 0})]
        [System.Int16]$LockoutDuration,
        
        [Parameter()]
        [ValidateScript({$_ -ge 10})]
        [System.UInt16]$MaxServiceAge,
        
        [Parameter()]
        [ValidateRange(0,99999)]
        [System.UInt16]$MaxTicketAge,
        
        [Parameter()]
        [ValidateRange(0,99999)]
        [System.UInt16]$MaxRenewAge,
        
        [Parameter()]
        [ValidateRange(0,99999)]
        [System.UInt16]$MaxClockSkew,
        [System.UInt16]$TicketValidateClient,

        [Parameter()]
        [ValidateSet("Present","Absent")]
        [System.String]$Ensure = "Present",

        [Parameter(Mandatory=$true)]
        [ValidateSet("MinimumPasswordAge","MaximumPasswordAge","MinimumPasswordLength","PasswordComplexity","PasswordHistorySize","LockoutBadCount","ForceLogoffWhenHourExpire","NewAdministratorName","NewGuestName","ClearTextPassword","LSAAnonymousNameLookup","EnableAdminAccount","EnableGuestAccount","ResetLockoutCount","LockoutDuration","MaxServiceAge","MaxTicketAge","MaxRenewAge","MaxClockSkew","TicketValidateClient")]
        [System.String]$Name
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
    $tmpFile = Join-Path -Path $env:SystemRoot -ChildPath "\security\database\temppol.inf"
    $new_secdb = Join-Path -Path $env:SystemRoot -ChildPath "\security\database\tmpsecedit.sdb"
    
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
            if ([System.Int]::TryParse($KeyPair.value, [ref]$Value))
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
    
    $PowerShellProcess = new-object System.Diagnostics.Process
    $PowerShellProcess.StartInfo.Filename = "secedit.exe"
    $PowerShellProcess.StartInfo.Arguments = " /configure /db $new_secdb /cfg $tmpfile /overwrite /quiet"
    $PowerShellProcess.StartInfo.RedirectStandardOutput = $True
    $PowerShellProcess.StartInfo.UseShellExecute = $false
    $PowerShellProcess.start() | Out-Null
    $PowerShellProcess.WaitForExit('10') | Out-Null
    [System.String] $process = $PowerShellProcess.StandardOutput.ReadToEnd();
    
    Remove-Item $tmpfile -Force
}

function Test-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [Parameter()]
        [ValidateRange(-1, 999)]
        [ValidateScript({$_ -ne 0})]
        [System.Int16]$MinimumPasswordAge,
        
        [Parameter()]
        [ValidateRange(0,999)]
        [System.UInt16]$MaximumPasswordAge,

        [Parameter()]
        [System.UInt16]$MinimumPasswordLength,
        
        [Parameter()]
        [System.UInt16]$PasswordComplexity,
        
        [Parameter()]
        [System.UInt16]$PasswordHistorySize,
        
        [Parameter()]
        [System.UInt16]$LockoutBadCount,
        
        [Parameter()]
        [System.UInt16]$ForceLogoffWhenHourExpire,
        
        [Parameter()]
        [System.String]$NewAdministratorName,
        
        [Parameter()]
        [System.String]$NewGuestName,

        [Parameter()]
        [System.UInt16]$ClearTextPassword,
        
        [Parameter()]
        [System.UInt16]$LSAAnonymousNameLookup,
        
        [Parameter()]
        [System.UInt16]$EnableAdminAccount,
        
        [Parameter()]
        [System.UInt16]$EnableGuestAccount,

        [Parameter()]
        [System.Int16]$ResetLockoutCount,
        
        [Parameter()]
        [ValidateRange(-1, 99999)]
        [ValidateScript({$_ -ne 0})]
        [System.Int16]$LockoutDuration,
        
        [Parameter()]
        [ValidateScript({$_ -ge 10})]
        [System.UInt16]$MaxServiceAge,
        
        [Parameter()]
        [ValidateRange(0,99999)]
        [System.UInt16]$MaxTicketAge,
        
        [Parameter()]
        [ValidateRange(0,99999)]
        [System.UInt16]$MaxRenewAge,
        
        [Parameter()]
        [ValidateRange(0,99999)]
        [System.UInt16]$MaxClockSkew,
        [System.UInt16]$TicketValidateClient,

        [Parameter()]
        [ValidateSet("Present","Absent")]
        [System.String]$Ensure = "Present",

        [Parameter(Mandatory=$true)]
        [ValidateSet("MinimumPasswordAge","MaximumPasswordAge","MinimumPasswordLength","PasswordComplexity","PasswordHistorySize","LockoutBadCount","ForceLogoffWhenHourExpire","NewAdministratorName","NewGuestName","ClearTextPassword","LSAAnonymousNameLookup","EnableAdminAccount","EnableGuestAccount","ResetLockoutCount","LockoutDuration","MaxServiceAge","MaxTicketAge","MaxRenewAge","MaxClockSkew","TicketValidateClient")]
        [System.String]$Name
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
    
    $ini = Get-TargetResource -Name $Name

    $returnValue = $true
    foreach ($header in $headers)
    {
        foreach ($KeyPair in ($PSBoundParameters.GetEnumerator() | Where-Object {$headerSettings[$_.Key] -eq $header}))
        {
            if ($ini.ContainsKey($header))
            {
                if ($ini[$header][$KeyPair.Key] -eq $KeyPair.Value)
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

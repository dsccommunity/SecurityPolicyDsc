Import-Module -Name (Join-Path -Path ( Split-Path $PSScriptRoot -Parent ) `
                               -ChildPath 'SecurityPolicyResourceHelper\SecurityPolicyResourceHelper.psm1') `
                               -Force

$script:localizedData = Get-LocalizedData -ResourceName 'MSFT_SecuritySetting'

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
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [Parameter(Mandatory=$true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName=$true)]
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
            $ini[$section][$name] = $value.Trim()
            continue
        } 
        "(.+ )\s*=(.*)"  # Key
        {
            $name,$value = $matches[1..2]
            $ini[$section][$name.Trim()] = $value.Trim()
            # Need to replace double quotes with `"
            continue
        }
        "\`"(.*)`",(.*)$" 
        { 
            $name, $value = $matches[1..2]
            $ini[$section][$name.Trim()] = $value.Trim()
            continue
        }
    }
    return $ini
}

function Get-SecuritySettings
{
    [CmdletBinding()]
    param()
    
    $file = Join-Path -Path $env:SystemRoot -ChildPath "\security\database\temppol.inf"
    Write-Verbose -Message ($script:localizedData.CreatingTmpFile -f $file)
    
    $PowerShellProcess = new-object System.Diagnostics.Process
    $PowerShellProcess.StartInfo.Filename = "secedit.exe"
    $PowerShellProcess.StartInfo.Arguments = " /export /cfg $file /areas securitypolicy"
    $PowerShellProcess.StartInfo.RedirectStandardOutput = $True
    $PowerShellProcess.StartInfo.UseShellExecute = $false
    $PowerShellProcess.Start() | Out-Null
    $PowerShellProcess.WaitForExit('10') | Out-Null
    [System.String] $process = $PowerShellProcess.StandardOutput.ReadToEnd();

    $ini = Get-IniContent -Path $file
    Remove-Item $file -Force
    return $ini
}

function Set-SecuritySettings
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        [string]$secDB,

        [Parameter(Mandatory=$true)]
        [string]$tmpFile
    )
    
    $PowerShellProcess = new-object System.Diagnostics.Process
    $PowerShellProcess.StartInfo.Filename = "secedit.exe"
    $PowerShellProcess.StartInfo.Arguments = " /configure /db $secDB /cfg $tmpfile /overwrite /quiet"
    $PowerShellProcess.StartInfo.RedirectStandardOutput = $True
    $PowerShellProcess.StartInfo.UseShellExecute = $false
    $PowerShellProcess.Start() | Out-Null
    $PowerShellProcess.WaitForExit('10') | Out-Null
    [System.String] $process = $PowerShellProcess.StandardOutput.ReadToEnd();
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
    
    $ini = Get-SecuritySettings
    
    $returnHash = @{}
    $values = "MinimumPasswordAge","MaximumPasswordAge","MinimumPasswordLength","PasswordComplexity","PasswordHistorySize","LockoutBadCount","ForceLogoffWhenHourExpire","NewAdministratorName","NewGuestName","ClearTextPassword","LSAAnonymousNameLookup","EnableAdminAccount","EnableGuestAccount","ResetLockoutCount","LockoutDuration","MaxServiceAge","MaxTicketAge","MaxRenewAge","MaxClockSkew","TicketValidateClient"
    foreach ($value in $values)
    {
        $returnHash.$value = $ini[$headerSettings[$value]].$value
    }
    
    $returnHash.Name = $Name
    
    return $returnHash
}

function Set-TargetResource
{
    [CmdletBinding()]
    param
    (
        [Parameter()]
        [ValidateRange(-1, 999)]
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
        Write-Error $script:localizedData.NoValuesSpecified
    }

    # Find out what sections we are setting.
    $PSBoundParameters.Remove("Ensure")
    $PSBoundParameters.Remove("Name")
    $headers = ($PSBoundParameters.GetEnumerator() | ForEach-Object { $headerSettings[$_.Key] } | Group-Object).Name
    
    $ini = Get-SecuritySettings
    $tmpFile = Join-Path -Path $env:SystemRoot -ChildPath "\security\database\temppol.inf"
    $newSecDB = Join-Path -Path $env:SystemRoot -ChildPath "\security\database\tmpsecedit.sdb"
    
    Write-Verbose -Message ($script:localizedData.CreatingTmpFile -f $tmpFile)
    Write-Verbose -Message ($script:localizedData.CreatingTmpFile -f $newSecDB)

    foreach ($header in $headers)
    {
        foreach ($keyPair in $PSBoundParameters.GetEnumerator())
        {
            try
            {
                $ini[$header][$keyPair.Key] = $keyPair.Value
            }
            catch
            {
                Write-Error $script:localizedData.FailureSettingKey -f $keyPair.Key, $keyPair.Value
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
    
        foreach ($keyPair in $ini[$header].GetEnumerator())
        {
            $Value = 1
            if ([System.Int32]::TryParse($keyPair.value, [ref]$Value))
            {
                "$($keyPair.Name) = $Value" | Out-File $tmpFile -Append
            }
            else
            {
                "$($keyPair.Name) = `"$($keyPair.Value)`"" | Out-File $tmpFile -Append 
            }
        }
    }
    
    "[Version]" | Out-File $tmpfile -Append
    "signature=`"`$CHICAGO`$`"" | Out-File $tmpfile -Append
    "Revision=1" | Out-File $tmpfile -Append
    
    Set-SecuritySettings -secDB $newSecDB -tmpFile $tmpFile

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
        Write-Error $script:localizedData.NoValuesSpecified
        return $false
    }
        
    # Find out what sections we are setting.
    $PSBoundParameters.Remove("Ensure") | Out-Null
    $PSBoundParameters.Remove("Name") | Out-Null
    $headers = ($PSBoundParameters.GetEnumerator() | ForEach-Object { $headerSettings[$_.Key] } | Group-Object).Name
    
    $ini = Get-SecuritySettings

    $returnValue = $true
    foreach ($header in $headers)
    {
        foreach ($keyPair in ($PSBoundParameters.GetEnumerator() | Where-Object {$headerSettings[$_.Key] -eq $header}))
        {
            if ($ini.ContainsKey($header))
            {
                if ([int]$ini[$header][$keyPair.Key] -eq $keyPair.Value)
                {
                    Write-Verbose -Message ($script:localizedData.TestSuccess -f $keyPair.Key, $keyPair.Value) 
                }
                else
                {
                    Write-Verbose -Message ($script:localizedData.TestFailure -f $keyPair.Key, $keyPair.Value) 
                    $returnValue = $false
                }
            }
            else
            {
                Write-Verbose -Message ($script:localizedData.SectionError -f $header) 
                $returnValue = $false
            }
        }
    }
    
    return $returnValue
}


Export-ModuleMember -Function *-TargetResource

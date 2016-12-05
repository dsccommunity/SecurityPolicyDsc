
Import-Module -Name (Join-Path -Path ( Split-Path $PSScriptRoot -Parent ) `
                               -ChildPath 'SecurityPolicyResourceHelper\SecurityPolicyResourceHelper.psm1') `
                               -Force

$script:localizedData = Get-LocalizedData -ResourceName 'MSFT_SecurityTemplate'

<#
    .SYNOPSIS
        Gets the path of the current policy template.
    .PARAMETER Path
        Not used in Get-TargetResource.
#>
function Get-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('Yes')]
        [String]
        $IsSingleInstance,

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Path
    )

    $securityCdmlets = Get-Module -Name SecurityCmdlets -ListAvailable
    $currentUserRightsInf = ([system.IO.Path]::GetTempFileName()).Replace('tmp','inf')

    if ($securityCdmlets)
    {
        Backup-SecurityPolicy -Path $currentUserRightsInf
        $templateFileName = Format-SecurityPolicyFile -Path $currentUserRightsInf
    }
    else
    {
        Get-SecurityTemplate -Path $currentUserRightsInf | Out-Null
        $templateFileName = $currentUserRightsInf
    }

    $returnValue = @{
        Path = [System.String]$templateFileName
        IsSingleInstance = 'Yes'
    }

    $returnValue    
}

<#
    .SYNOPSIS
        Gets the path of the desired policy template.
    .PARAMETER Path
        Specifies the path to the policy template.
#>
function Set-TargetResource
{
    [CmdletBinding()]
    param
    (
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('Yes')]
        [String]
        $IsSingleInstance,

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Path
    )

    $securityCdmlets = Get-Module -Name SecurityCmdlets -ListAvailable

    if ($securityCdmlets)
    {
        Restore-SecurityPolicy -Path $Path
    }
    else
    {
        $seceditOutput = "$env:TEMP\Secedit-OutPut.txt"
    
        Invoke-Secedit -UserRightsToAddInf $Path -SecEditOutput $seceditOutput
    }
    # Verify secedit command was successful
    $testSuccuess = Test-TargetResource @PSBoundParameters

    if ($testSuccuess -eq $true)
    {
        Write-Verbose -Message ($script:localizedData.TaskSuccess)
    }
    else
    {
        $seceditResult = Get-Content $seceditOutput
        Write-Error -Message ($script:localizedData.TaskSuccessFail)        
    }
}

<#
    .SYNOPSIS
        Gets the path of the desired policy template.
    .PARAMETER Path
        Specifies the path to the policy template.
#>
function Test-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $IsSingleInstance, 

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Path
    )
    
    $securityCdmlets = Get-Module -Name SecurityCmdlets -ListAvailable
    $currentUserRightsInf = ([system.IO.Path]::GetTempFileName()).Replace('tmp','inf')
    $fileExists = Test-Path -Path $Path

    if ($fileExists -eq $false)
    {
        throw ($script:localizedData.PathNotFound) -f $Path
    }

    if ($securityCdmlets)
    {
        Backup-SecurityPolicy -Path $currentUserRightsInf
    }
    else
    {
        Get-SecurityTemplate -Path $currentUserRightsInf | Out-Null
    }
    
    $desiredPolicies = (Get-UserRightsAssignment -FilePath $Path).'Privilege Rights'
    $currentPolicies = (Get-UserRightsAssignment -FilePath $currentUserRightsInf).'Privilege Rights'
    
    $policyNames = $desiredPolicies.keys

    $policiesMatch = $false

    foreach ($policy in $policyNames)
    {
        if ($null -eq $currentPolicies[$policy] -or $null -eq $desiredPolicies[$policy])
        {
            $policiesMatch = $null -eq $currentPolicies[$policy] -and $null -eq $desiredPolicies[$policy]
        }
        else
        {
            $policiesMatch = $null -eq ( Compare-Object -ReferenceObject ($currentPolicies[$policy]).Trim() -DifferenceObject ($desiredPolicies[$policy]).Trim() )
        }

        if(-not $policiesMatch)
        {
            Write-Verbose -Message ($script:localizedData.NotDesiredState -f $Policy)
            return $false
        } 
    }

    # If the code made it this far all policies must be in a desired state
    return $true
}

<#
    .SYNOPSIS
        Removes the other security areas from policy template file so only settings for user rights assignments are returned.
    .PARAMETER Path
        Specifies the file to the template to be parsed.
#>
function Format-SecurityPolicyFile
{
    [OutputType([String])]
    [CmdletBinding()]
    param
    (
        [System.String]$Path
    )

    $outputPath = ([system.IO.Path]::GetTempFileName()).Replace('tmp','inf')
    $content = Get-Content -Path $Path 

    $privilegeRightsMatch = Select-String -Path $Path -Pattern "[Privilege Rights]" -SimpleMatch
    $endOfFileMatch = Select-String -Path $Path -Pattern "Revision=1" -SimpleMatch

    $startOfFile = $privilegeRightIndex.LineNumber -1
    $endOfFile = $endOfFileMatch.LineNumber

    $content[$startOfFile..$endOfFile] | Out-File -FilePath $outputPath

    $outputPath
}

<#
    .SYNOPSIS
        Invokes secedit.exe to create an INF file of the current policies
#>
function Get-SecurityTemplate
{
    [OutputType([String])]
    [CmdletBinding()]   
    param
    (
        [System.String]$Path
    )
    
    $secedit = secedit.exe /export /cfg $Path /areas "USER_Rights"    
}

Export-ModuleMember -Function *-TargetResource


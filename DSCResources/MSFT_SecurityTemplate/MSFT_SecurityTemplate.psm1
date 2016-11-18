
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
        Get-SecInfFile -Path $currentUserRightsInf | Out-Null
        $templateFileName = $currentUserRightsInf
    }

    $returnValue = @{
        Path = [System.String]$templateFileName
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
    $testSuccuess = Test-TargetResource -Path $Path -Verbose:0

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
        Get-SecInfFile -Path $currentUserRightsInf | Out-Null
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

Export-ModuleMember -Function *-TargetResource


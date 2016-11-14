
$properties = @()
$properties += New-xDscResourceProperty -Name Path -Type String -Attribute Key -Description "Path to Inf the defines the desired security policies"

$securityTemplateParameters = @{
    Name = 'MSFT_SecurityTemplate'
    Property = $properties
    FriendlyName = 'SecurityTemplate'
    ModuleName = 'SecurityPolicyDsc'
    Path = 'C:\Program Files\WindowsPowerShell\Modules\'
}

New-xDscResource @securityTemplateParameters

$properties = @()
$properties += New-xDscResourceProperty -Name Path -Type String -Attribute Key -Description "Path to Inf the defines the desired security policies"

$secInfParameters = @{
    Name = 'MSFT_SecInf'
    Property = $properties
    FriendlyName = 'SecInf'
    ModuleName = 'SeceditDSC'
    Path = 'C:\Program Files\WindowsPowerShell\Modules\'
}

New-xDscResource @secInfParameters

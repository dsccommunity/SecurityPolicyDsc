@{
    # Set up a mini virtual environment...
    PSDependOptions             = @{
        AddToPath  = $true
        Target     = 'output\RequiredModules'
        Parameters = @{
           Repository = ''
        }
    }

    InvokeBuild                 = 'latest'
    PSScriptAnalyzer            = 'latest'
    Pester                      = 'latest'
    Plaster                     = 'latest'
    ModuleBuilder               = '1.0.0'
    ChangelogManagement         = 'latest'
    Sampler                     = 'latest'
    MarkdownLinkCheck           = 'latest'
    'DscResource.Test'          = 'latest'
    'DscResource.AnalyzerRules' = 'latest'
    xDscResourceDesigner        = 'latest'
    'DscResource.DocGenerator'  = 'latest'
}

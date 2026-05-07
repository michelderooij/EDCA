@{
    RootModule        = 'EDCA.psm1'
    ModuleVersion     = '1.0.0.3'
    GUID              = '3bc65f39-03b1-4d4d-a3af-b88f21dac09b'
    Author            = 'Michel de Rooij'
    CompanyName       = 'EighTwOne'
    Copyright         = '(c) Michel de Rooij. All rights reserved.'
    Description       = 'Exchange Deployment & Compliance Assessment — collects configuration data from Exchange 2016, Exchange 2019, and Exchange SE, evaluates against best-practice and compliance controls, and produces an interactive HTML report.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('Invoke-EDCA')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    PrivateData       = @{
        PSData = @{
            Tags         = @('Exchange', 'Compliance', 'Assessment', 'Security', 'Report')
            ProjectUri   = 'https://github.com/michelderooij/EDCA'
            ReleaseNotes = 'See CHANGELOG.md'
        }
    }
}

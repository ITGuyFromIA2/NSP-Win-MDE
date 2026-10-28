@{
    # Settings for Find-NSPClientReference (NSP.RepoTools). Tracked: name what is accepted, never a client.
    ClientSweep = @{
        # ProcMon filter fixtures (binary, byte-identical references). Their strings are the filter
        # values from the tests: commercial app names, MsSense.exe, CreateFile, \Clients\.
        ExcludePath = @('Tests/Fixtures/*.pmc')
        Allow = @(
            # Placeholder file server in tests and fixtures.
            '\\APP01\apps'
        )
        AllowPattern = @()
    }
}

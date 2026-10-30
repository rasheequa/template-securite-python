/*
 * Règles YARA d'exemple pour le TP2.
 * Ajoutez-en au moins deux à vous.
 */

rule Suspicious_Downloader
{
    meta:
        author = "esgi"
        description = "Telechargement + execution d'une charge distante"
    strings:
        $dll = "urlmon.dll" nocase
        $api = "URLDownloadToFile" nocase
        $run = "WinExec" nocase
    condition:
        2 of them
}

rule Reverse_Shell
{
    meta:
        author = "esgi"
        description = "Socket sortante + shell de commande"
    strings:
        $ws = "WSASocket" nocase
        $sh = "cmd.exe" nocase
    condition:
        $ws and $sh
}

rule Keylogger
{
    meta:
        author = "esgi"
        description = "Hook clavier"
    strings:
        $hook = "SetWindowsHookEx" nocase
        $key = "GetAsyncKeyState" nocase
    condition:
        any of them
}

rule Has_Mutex {
    meta:
        description = "Mutex name style : Global\\xxx (prevents double infection)"
        author = "Leo"
    strings:
        $m = /Global\\[A-Za-z0-9]{4,}/
    condition:
        $m
}

rule Persistence_Run_Key {
    meta:
        description = "Registry Run key: malware starts automatically"
        author = "Rasheequa"
    strings:
        $run = "CurrentVersion\\Run" nocase
    condition:
        $run
}

rule C2_Gate_URL {
    meta:
        description = "URL used to communicate with a C2 server (gate.php)"
        author = "Leo"
    strings:
        $gate = /https?:\/\/[a-z0-9.-]+\/gate\.php/ nocase
    condition:
        $gate
}


rule Network_Backdoor {
    meta:
        description = "Windows socket/command shell: network backdoor"
        author = "Rasheequa"
    strings:
        $sock = "WSASocket" nocase
        $cmd  = "cmd.exe" nocase
    condition:
        all of them
}

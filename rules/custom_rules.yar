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

rule Keylogger_APIs {
    meta:
        description = "Keyboard capture APIs"
        author = "Leo"
    strings:
        $hook = "SetWindowsHookEx" nocase
        $key  = "GetAsyncKeyState" nocase
    condition:
        any of them
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

rule Suspicious_Downloader {
    meta:
        description = "Detects a suspicious download (urlmon.dll / URLDownloadToFile)"
        author = "Rasheequa"
    strings:
        $a = "urlmon.dll" nocase
        $b = "URLDownloadToFile" nocase
    condition:
        any of them
}

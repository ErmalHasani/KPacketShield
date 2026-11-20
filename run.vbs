Set WshShell = CreateObject("WScript.Shell")
WshShell.CurrentDirectory = "bin"
WshShell.Run "kpacketshield-ui.exe", 0, False

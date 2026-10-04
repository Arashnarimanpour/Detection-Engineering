Github Link of SIGMA Rule : [Detects Obfuscated Powershell via COMPRESS OBFUSCATION](https://github.com/SigmaHQ/sigma/blob/8eaafff1f2845a696050e05e72ba1140ee190698/rules/windows/builtin/security/win_security_invoke_obfuscation_via_compress_services_security.yml#L17)



**First Windows Rule :**
```
index=windows EventCode=4697 
Service_File_Name="*new-object*" 
Service_File_Name="*text.encoding]::ascii*" 
Service_File_Name="*readtoend*" 
Service_File_Name IN ("*system.io.compression.deflatestream*", "*system.io.streamreader*")
```


**Second Rule For Powershell :**
```
index=powershell EventCode=4104
    OR "new-service"
    OR "wmic"
    OR "win32_service"

"*new-object*" 
"*text.encoding]::ascii*" 
"*readtoend*"
(
    "*system.io.compression.deflatestream*"
    OR "*system.io.streamreader*"
)
```


**Second Rule For Powershell :**
```
index=powershell EventCode=4104
ScriptBlockText IN ("*sc.exe*","*new-service*","*wmic*","*win32_service*")
ScriptBlockText="*new-object*"
ScriptBlockText="*text.encoding]::ascii*"
ScriptBlockText="*readtoend*"
(
    ScriptBlockText="*system.io.compression.deflatestream*"
    OR ScriptBlockText="*system.io.streamreader*"
)
```

**description** : Detects UTF-8 and UTF-16 Base64 encoded powershell 'Invoke-' calls

**[SIGMA Link](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_powershell_base64_invoke.yml?utm_source=chatgpt.com)**


##### **SYSMON UseCase :**  
 
```
index=sysmon  EventCode=1
Image IN ("*\\powershell.exe", "*\\pwsh.exe") OR 
OriginalFileName IN ("PowerShell.EXE", "pwsh.dll") CommandLine="* -e*" 
CommandLine IN ("*SQBuAHYAbwBrAGUALQ*", "*kAbgB2AG8AawBlAC0A*", "*JAG4AdgBvAGsAZQAtA*", "*SW52b2tlL*", "*ludm9rZS*", "*JbnZva2Ut*")
| fillnull value=Null
| stats  min(_time) as firstTime max(_time) as lastTime by host CommandLine Image OriginalFileName ParentCommandLine ParentImage
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)`
```




##### **POWERSHELL UseCase :**
```
index=powershell  EventCode=4104
ScriptBlockText IN ("*SQBuAHYAbwBrAGUALQ*", "*kAbgB2AG8AawBlAC0A*", "*JAG4AdgBvAGsAZQAtA*", "*SW52b2tlL*", "*ludm9rZS*", "*JbnZva2Ut*")
| fillnull value=Null
| stats  min(_time) as firstTime max(_time) as lastTime by host ScriptBlockText 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)`
```




##### **DATAMODEL UseCase :**
```
| tstats  count summariesonly=true min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes 
where 
(
Processes.original_file_name IN ("PowerShell.EXE", "pwsh.dll") 
Processes.process_exec IN ("*\\powershell.exe", "*\\pwsh.exe") OR
Processes.process_path IN ("*\\powershell.exe", "*\\pwsh.exe") 
)
Processes.process="* -e*" 

Processes.process IN ("*SQBuAHYAbwBrAGUALQ*", "*kAbgB2AG8AawBlAC0A*", "*JAG4AdgBvAGsAZQAtA*", "*SW52b2tlL*", "*ludm9rZS*", "*JbnZva2Ut*")

by   Processes.dest 
     Processes.original_file_name 
     Processes.user
     Processes.parent_process 
     Processes.parent_process_exec 
     Processes.parent_process_guid 
     Processes.parent_process_name 
     Processes.parent_process_path 
     Processes.process
     Processes.process_exec
     Processes.process_guid 
     Processes.process_hash   
     Processes.process_name
     Processes.process_path
     Processes.user_id  
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)`
```

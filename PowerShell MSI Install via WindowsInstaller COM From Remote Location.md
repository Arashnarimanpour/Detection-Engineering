
I wrote 2 UseCases, one is Normal & Abother is with Datamodel.

Normal UseCase with **index=powershell** :
```
index=powershell EventCode IN (4104,4103)
(
    ScriptBlockText="*-ComObject*"
    AND ScriptBlockText="*InstallProduct(*"
)
AND (
    ScriptBlockText="*http*"
    OR ScriptBlockText="*\\\\*"
)
NOT (
    ScriptBlockText="*://127.0.0.1*"
    OR ScriptBlockText="*://localhost*"
)
| stats
    count AS event_count
    earliest(_time) AS firstTime
    latest(_time) AS lastTime
    values(ScriptBlockText) AS script_block
    values(UserID) AS user
    BY host
```



My Second UseCaee with DataModel :
```
| tstats summariesonly=true count
    earliest(_time) AS firstTime
    latest(_time) AS lastTime
    values(Processes.process) AS script_block
    values(Processes.user) AS user 
    FROM datamodel="Endpoint.Processes"
 where  Processes.process IN ("*-ComObject*" , "*InstallProduct(*") 
 AND 
 (Processes.process IN ("*\\\\*" , "*http*"))
  AND 
    (
        Processes.process_name IN ("powershell.exe","powershell_ise.exe","pwsh.exe")
        OR Processes.original_file_name IN ("PowerShell_ISE.EXE","PowerShell.EXE","pwsh.dll")
    )
    NOT 
    (Processes.process IN ("*://localhost*" , "*://127.0.0.1*"))
        BY Processes.dest
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`

```
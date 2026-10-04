**description**: Detects potential path traversal attempt via cmd.exe. Could indicate possible command/argument confusion/hijacking

[SIGMA Link](description: Detects potential path traversal attempt via cmd.exe. Could indicate possible command/argument confusion/hijacking)


### Sysmon Rule
```
index=sysmon  EventCode=1 
(
ParentImage="*\\cmd.exe" OR Image="*\\cmd.exe" OR OriginalFileName="cmd.exe"

(ParentCommandLine IN ("*/c*", "*/k*", "*/r*")) OR
(CommandLine IN ("*/c*", "*/k*", "*/r*")) 


ParentCommandLine="*../..*" OR
CommandLine="*../..*" 
NOT CommandLine="*\\Tasktop\\keycloak\\bin\\/../../jre\\bin\\java*"
)
| fillnull value=Null
| stats  min(_time) as firstTime max(_time) as lastTime by host CommandLine Image OriginalFileName ParentCommandLine ParentImage
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)`
```


### Data Model Rule :
```
| tstats  count summariesonly=true min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes 
where 
(
Processes.original_file_name="Cmd.exe" OR 
Processes.process_exec="cmd.exe"
Processes.process_path="*cmd.exe*"

Processes.parent_process IN ("*/c*", "*/k*", "*/r*") OR 
Processes.process IN ("*/c*", "*/k*", "*/r*") 

Processes.parent_process="../.." OR
Processes.process="*../..*"
NOT Processes.process="*\\Tasktop\\keycloak\\bin\\/../../jre\\bin\\java*"
)
by   Processes.dest 
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

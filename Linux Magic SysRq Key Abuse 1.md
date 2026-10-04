### First Search 
**This search belong to Splunk Research :**
```
`linux_auditd` 
(type=PATH OR type=CWD) 
| rex "msg=audit\([^)]*:(?<audit_id>\d+)\)" 
 
| stats 
  values(type) as types 
  values(name) as names 
  values(nametype) as nametype 
  values(cwd) as cwd_list 
  values(_time) as event_times 
  by audit_id, host 
 
| eval current_working_directory = coalesce(mvindex(cwd_list, 0), "N/A") 
| eval candidate_paths = mvmap(names, if(match(names, "^/"), names, current_working_directory + "/" + names)) 
| eval matched_paths = mvfilter(match(candidate_paths, ".*/proc/sysrq-trigger|.*/proc/sys/kernel/sysrq|.*/etc/sysctl.conf")) 
| eval match_count = mvcount(matched_paths) 
| eval reconstructed_path = mvindex(matched_paths, 0) 
| eval e_time = mvindex(event_times, 0) 
| where match_count > 0 
| rename host as dest 
 
| stats count min(e_time) as firstTime max(e_time) as lastTime 
  values(nametype) as nametype 
  by current_working_directory 
     reconstructed_path 
     match_count 
     dest 
     audit_id
 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)`
```Linux Magic SysRq Key Abuse```
```


---

### Second Search 
**This search is a bit simpler :**

```
index=auditd type=PATH
(
    name="/proc/sysrq-trigger"
    OR name="/proc/sys/kernel/sysrq"
    OR name="/etc/sysctl.conf"
)
| eval activity=case(
    name="/proc/sysrq-trigger", "Magic SysRq trigger accessed",
    name="/proc/sys/kernel/sysrq", "Runtime SysRq configuration accessed",
    name="/etc/sysctl.conf", "Persistent SysRq configuration accessed",
    true(), "Unknown SysRq activity"
)
| eval severity=case(
    name="/proc/sysrq-trigger", "high",
    name="/proc/sys/kernel/sysrq", "medium",
    name="/etc/sysctl.conf", "medium"
)
| rex "msg=audit\([^)]*:(?<audit_id>\d+)\)" 

| table _time host name nametype inode mode ouid ogid key activity severity  audit_id
| sort - _time
```Linux Magic SysRq Key Abuse```
```

---

### Third Search 
**This search most simple search with less usage and map function :**
```
index=auditd audit_id=* type=PATH
(
    name="*/sysrq"
    OR name="*/sysctl.conf"
    OR name="*/sysrq-trigger"
)
| map search="search index=auditd audit_id=$audit_id$"
```| table AUID name command audit_id proctitle
   | table _time host audit_id name nametype inode mode ouid ogid key```
| stats values(AUID) as Original_User , values(name) as Target_Path , values(nametype) as ChangeType , values(ouid) as Owner_id , values(proctitle) as Original_Command by audit_id _time
| sort - _time
```
description: Detects Obfuscated Powershell via use MSHTA in Scripts

[Git-Hub Link](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_hktl_invoke_obfuscation_via_use_mhsta.yml?utm_source=chatgpt.com)

### First Format of Query With SYSMON 
```
index=sysmon dest="soc-test01.zarin.local" EventCode=1
CommandLine="*set*"
CommandLine IN ("*&&*", "*&amp;&amp*")
CommandLine="*mshta*"
CommandLine="*vbscript:createobject*"
CommandLine="*.run*"
CommandLine="*(window.close)*"
| stats
    count AS execution_count
    earliest(_time) AS firstTime
    latest(_time) AS lastTime
    values(Image) AS process_path
    values(CommandLine) AS command_line
    values(ParentImage) AS parent_process
    values(User) AS user
    BY host
```

### Second Format of Query With DataModel 
```
index=sysmon dest="soc-test01.zarin.local" EventCode=1
CommandLine="*set*"
CommandLine IN ("*&&*", "*&amp;&amp*")
CommandLine="*mshta*"
CommandLine="*vbscript:createobject*"
CommandLine="*.run*"
CommandLine="*(window.close)*"
| stats
    count AS execution_count
    earliest(_time) AS firstTime
    latest(_time) AS lastTime
    values(Image) AS process_path
    values(CommandLine) AS command_line
    values(ParentImage) AS parent_process
    values(User) AS user
    BY host
```


### Second & Best Format of Query 
```
index=powershell EventCode=4104
ScriptBlockText="*set*"
ScriptBlockText IN ("*&&*", "*&amp;&amp*")
ScriptBlockText="*mshta*"
ScriptBlockText="*vbscript:createobject*"
ScriptBlockText="*.run*"
ScriptBlockText="*(window.close)*"
```
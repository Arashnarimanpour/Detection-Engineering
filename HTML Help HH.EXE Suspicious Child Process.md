
Description : **Detects a suspicious child process of a Microsoft HTML Help (HH.exe)**



[SIGMA Link](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_hh_html_help_susp_child_process.yml?utm_source=chatgpt.com)

I write 2 type of rule , **SYSMON** Rule & **DATAMODEL** Rule , Based on logic of original SIGMA Rule.

**My SYSMON Rule :**  
```
index=sysmon 
ParentImage="*\\hh.exe" 
Image IN 
("*\\CertReq.exe", "*\\CertUtil.exe", "*\\cmd.exe", "*\\cscript.exe", "*\\installutil.exe", "*\\MSbuild.exe", "*\\MSHTA.EXE", "*\\msiexec.exe", "*\\powershell.exe", "*\\pwsh.exe", "*\\regsvr32.exe", "*\\rundll32.exe", "*\\schtasks.exe", "*\\wmic.exe", "*\\wscript.exe")

| fillnull value=Null
| stats  min(_time) as firstTime max(_time) as lastTime by host CommandLine Image OriginalFileName ParentCommandLine ParentImage
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)`
```




**My DATAMODEL Rule :**  

```
| tstats  count summariesonly=true min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes 
where 
(
Processes.parent_process_exec="*hh.exe" OR 
Processes.parent_process_path="*hh.exe" OR
Processes.parent_process="*\\hh.exe"

Processes.process_path IN ("*\\CertReq.exe", "*\\CertUtil.exe", "*\\cmd.exe", "*\\cscript.exe", "*\\installutil.exe", "*\\MSbuild.exe", "*\\MSHTA.EXE", "*\\msiexec.exe", "*\\powershell.exe", "*\\pwsh.exe", "*\\regsvr32.exe", "*\\rundll32.exe", "*\\schtasks.exe", "*\\wmic.exe", "*\\wscript.exe")
OR 
Processes.process IN ("*\\CertReq.exe", "*\\CertUtil.exe", "*\\cmd.exe", "*\\cscript.exe", "*\\installutil.exe", "*\\MSbuild.exe", "*\\MSHTA.EXE", "*\\msiexec.exe", "*\\powershell.exe", "*\\pwsh.exe", "*\\regsvr32.exe", "*\\rundll32.exe", "*\\schtasks.exe", "*\\wmic.exe", "*\\wscript.exe")
)

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





***


#### Logic of Rule 

This rule looks for a very specific and suspicious process chain:

```
text
hh.exe
   ↓
cmd.exe / powershell.exe / mshta.exe / rundll32.exe / etc.
```

`hh.exe` is the legitimate Microsoft HTML Help viewer. Its normal purpose is to open `.chm` help files. A normal chain would usually be:

```text
user
  ↓
hh.exe
  ↓
display help content
```

The problem is that CHM files can contain active content, links, scripts, and HTML-based behavior. An attacker can send a malicious `.chm` file, often through phishing, and when the victim opens it, `hh.exe` can be abused to start another executable.

The attack flow can look like:

```text
Phishing attachment
      ↓
malicious .chm
      ↓
hh.exe
      ↓
powershell.exe
      ↓
attacker command
```

or:

```text
hh.exe
   ↓
cmd.exe
```

or:

```text
hh.exe
   ↓
mshta.exe
```

That is the core reason for the rule.

The rule says:

```yaml
ParentImage|endswith: '\hh.exe'
```

Meaning:

> The parent process must be `hh.exe`.

Then:

```yaml
Image|endswith:
  - '\cmd.exe'
  - '\powershell.exe'
  - '\mshta.exe'
  - '\rundll32.exe'
  ...
```

Meaning:

> Alert if `hh.exe` launches one of these powerful execution utilities.

The listed child processes are suspicious because many can execute code, scripts, DLLs, installers, or remote commands. For example:

- `cmd.exe` → command execution
    
- `powershell.exe` / `pwsh.exe` → PowerShell execution
    
- `cscript.exe` / `wscript.exe` → script execution
    
- `mshta.exe` → HTML/JavaScript/VBScript execution
    
- `rundll32.exe` → DLL execution
    
- `regsvr32.exe` → DLL/COM execution
    
- `msiexec.exe` → MSI execution
    
- `wmic.exe` → WMI-based execution
    
- `schtasks.exe` → scheduled task execution
    
- `certutil.exe` → can download/decode files
    
- `msbuild.exe` / `installutil.exe` → can be abused as signed Microsoft execution utilities
    

So the logic is essentially:

```text
Legitimate Windows help viewer
        +
unexpected execution-capable child process
        =
possible malicious CHM execution
```

This is why the severity is high: `hh.exe` normally should not be acting like a launcher for shells or LOLBins.

The MITRE mappings also reflect that. `T1566.001` relates to phishing attachments, `T1218` relates to signed binary proxy execution, and `T1059.*` covers script and command interpreters.

For SOC investigation, the most important fields are:

```
text
ParentImage
Image
CommandLine
ParentCommandLine
User
Hashes
CHM file path
```

The key question is: **what CHM file caused `hh.exe` to launch the child process, and what did that child process execute?**

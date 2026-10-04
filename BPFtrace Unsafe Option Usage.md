```
index=auditd sourcetype=auditd
(type=EXECVE OR type=PROCTITLE)
| eval command_line=coalesce(proctitle, cmdline, command, exe)
| where (
    match(command_line, "(?i)(^|\/)bpftrace(\s|$)")
    AND match(command_line, "(?i)(^|\s)--unsafe(\s|$)")
)
| eval detection_name="BPFtrace Unsafe Option Usage"
| eval severity="medium"
| eval mitre_tactic="Execution"
| eval mitre_technique="Unix Shell"
| eval mitre_technique_id="T1059.004"
| table _time host user uid auid exe comm command_line detection_name severity mitre_tactic mitre_technique mitre_technique_id
| sort - _time
```

Sigma Address :
[proc_creation_lnx_bpftrace_unsafe_option_usage](https://github.com/SigmaHQ/sigma/blob/2dbc894640dda893f3bfec6326c241df7b4b03b3/rules/linux/process_creation/proc_creation_lnx_bpftrace_unsafe_option_usage.yml#L12)
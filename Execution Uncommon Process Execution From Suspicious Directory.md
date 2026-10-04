
**The like of Elastic rule :**
[[New Hunt] Add Initial Linux Hunting Files](https://github.com/elastic/detection-rules/commit/f0b2cb7c87a3d43d6f9dd6fb560a79994d4939c1)

# The splunk rules which i made them 


## First Rule 
```
index=auditd
type IN ("SYSCALL","EXECVE","PROCTITLE")

| rex field=msg "audit\([^)]*:(?<audit_id>\d+)\)"

| where isnotnull(audit_id)


| stats
    earliest(_time) AS firstTime
    latest(_time) AS lastTime
    values(exe) AS executable
    values(comm) AS process
    values(proctitle) AS command_line
    values(uid) AS uid
    values(auid) AS auid
    values(euid) AS euid
    values(ppid) AS parent_pid
    values(key) AS audit_key
    BY host audit_id


| where
(
    mvfind(executable,"^/dev/shm/")>=0
    OR mvfind(executable,"^/var/www/")>=0
    OR mvfind(executable,"^/boot/")>=0
    OR mvfind(executable,"^/srv/")>=0
    OR mvfind(executable,"^/tmp/")>=0
    OR mvfind(executable,"^/var/tmp/")>=0
    OR mvfind(executable,"^/run/")>=0
    OR mvfind(executable,"^/var/run/")>=0
)


| where NOT (
    match(mvjoin(executable," "),
    "^/tmp/[0-9].*")

    OR

    match(mvjoin(executable," "),
    "^/var/tmp/[0-9].*")
)


| eval severity="medium"

| eval risk_reason=
"Execution from uncommon Linux writable/suspicious directory"


| rename host AS dest


| table
    firstTime
    lastTime
    dest
    audit_id
    executable
    process
    command_line
    uid
    auid
    euid
    severity
    risk_reason

| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 

| sort - firstTime
```



## Second Rule 
```
index=auditd type IN (EXECVE, SYSCALL, PROCTITLE)

| eval process_path=coalesce(exe,a0)

| where match(process_path,
"^/(dev/shm|var/www|boot|srv|tmp|var/tmp|run|var/run)/")

| where NOT match(process_path,"^/(tmp|var/tmp)/[0-9].*")

| eval severity="medium"

| eval risk_reason="Execution from uncommon Linux writable directory"

| table _time host process_path comm uid auid euid pid ppid proctitle severity risk_reason

| sort - _time
```



## Third Rule 
```
index=auditd type IN (EXECVE, SYSCALL, PROCTITLE)
(
    a0="/dev/shm/*"
    OR a0="/var/www/*"
    OR a0="/boot/*"
    OR a0="/srv/*"
    OR a0="/tmp/*"
    OR a0="/var/tmp/*"
    OR a0="/run/*"
    OR a0="/var/run/*"
)

| where NOT match(a0,"^/(tmp|var/tmp)/[0-9].*")

| eval severity="medium"
| eval risk_reason="Execution from suspicious Linux directory"

| table _time host a0 comm uid AUID euid pid ppid proctitle severity risk_reason
```
```
index=sysmon Image="*finger.exe*" EventCode IN (22,3)
| stats
    count AS event_count
    values(QueryResults) as QueryResults
    values(QueryName) as QueryName
    values(Image) as Image
    values(User) as User
    min(_time) AS firstTime
    max(_time) AS lastTime
    BY host 
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```
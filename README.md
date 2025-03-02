# Legion
Linux distro Malware scanner and heuristics model
---

## Why
- I have dreamed of building my own malware scan tool.
- I also wanted to learn "C" in a way to teach and allow facts to hold security at its highest. 
- I vow to help the UNIX world with our heart, mind and passions. 

## Where we are
- first test was stable but failed on (6) lines.
- looking to keep it high level and heuristic with updated resources.
- Wanting to tie in a SIEM tool, unknown which outside of Wazuh or Splink. 

## ideas:

**Headless for quick and low volume scans**
- keep the file local and fast, no prize for second place. 
**Agentless for VM and container based deployments**
-  Kubernetes audit logs or Falco rules, Legion could detect unusual processes or syscalls.
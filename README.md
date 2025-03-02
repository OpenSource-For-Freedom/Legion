
readme_content = """\
```
                                                        
@@@       @@@@@@@@   @@@@@@@@  @@@   @@@@@@   @@@  @@@  
@@@       @@@@@@@@  @@@@@@@@@  @@@  @@@@@@@@  @@@@ @@@  
@@!       @@!       !@@        @@!  @@!  @@@  @@!@!@@@  
!@!       !@!       !@!        !@!  !@!  @!@  !@!!@!@!  
@!!       @!!!:!    !@! @!@!@  !!@  @!@  !@!  @!@ !!@!  
!!!       !!!!!:    !!! !!@!!  !!!  !@!  !!!  !@!  !!!  
!!:       !!:       :!!   !!:  !!:  !!:  !!!  !!:  !!!  
 :!:      :!:       :!:   !::  :!:  :!:  !:!  :!:  !:!  
 :: ::::   :: ::::   ::: ::::   ::  ::::: ::   ::   ::  
: :: : :  : :: ::    :: :: :   :     : :  :   ::    :   
                                                        
```

# Legion

**Linux distro Malware scanner and heuristics model**  
---

## Why

- I have dreamed of building my own malware scan tool.
- I also wanted to learn **C** in a way to teach and allow facts to hold security at its highest.
- I vow to help the UNIX world with my **heart, mind, and passions**.
- We want to move away from signatures and push for heuristics.
## Where we are

- First test was stable but failed on **6** lines.
- Looking to keep it **high level and heuristic** with updated resources.
- Next step is to build the signature and whitelist requirment to an api, instead of a local txt. 
- Wanting to tie in a **SIEM tool**, unknown which outside of **Wazuh** or **Splunk**.

## Ideas

### **Headless for quick and low-volume scans**
- Keep the file local and fast, **no prize for second place**.

### **Agentless for VM and container-based deployments**
- Kubernetes audit logs or **Falco rules**, Legion could detect unusual processes or syscalls.
- API signature integration
- MLOp's .... yes pleaze. 
"""


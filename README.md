
```
 ██▓    ▓█████   ▄████  ██▓ ▒█████   ███▄    █ 
▓██▒    ▓█   ▀  ██▒ ▀█▒▓██▒▒██▒  ██▒ ██ ▀█   █ 
▒██░    ▒███   ▒██░▄▄▄░▒██▒▒██░  ██▒▓██  ▀█ ██▒
▒██░    ▒▓█  ▄ ░▓█  ██▓░██░▒██   ██░▓██▒  ▐▌██▒
░██████▒░▒████▒░▒▓███▀▒░██░░ ████▓▒░▒██░   ▓██░
░ ▒░▓  ░░░ ▒░ ░ ░▒   ▒ ░▓  ░ ▒░▒░▒░ ░ ▒░   ▒ ▒ 
░ ░ ▒  ░ ░ ░  ░  ░   ░  ▒ ░  ░ ▒ ▒░ ░ ░░   ░ ▒░
  ░ ░      ░   ░ ░   ░  ▒ ░░ ░ ░ ▒     ░   ░ ░ 
    ░  ░   ░  ░      ░  ░      ░ ░           ░ 
                                               
                                                        
          The Linux Malware Sentinel 



# ================ 𝕃𝔼𝔾𝕀𝕆ℕ ==================#
#                                            #
#    "Dwell on the beauty of life. Watch     #
#         the stars, and see yourself        #
#             running with them".            #
#             - Marcus Aurelius              #
#                                            #
# ========= STAGING AND PLANNING ===========#
```
**Linux distro Malware scanner and heuristics model**  
---

## Why

- I have dreamed of building my own malware scan tool.
- I also wanted to learn **C** in a way to teach and allow facts to hold security at its highest.
- I vow to help the UNIX world with my **heart, mind, and passions**.
- We want to move away from signatures and push for heuristics.

## Where we are

- First test was stable but failed on **6** lines.
- Developed an active `whitelist.txt` file for a baseline heuristic model. 
- Developed a <placeholder> `signatures.txt` file for a framework for building known threats.
- Looking to keep it **high level and heuristic** with updated resources.
- Next step is to build the signature and whitelist requirment to an api, instead of a local txt. 
- Wanting to tie in a **SIEM tool**, unknown which outside of **Wazuh** or **Splunk**.

## Integrations 

- **Rust-based scanner (`scanner.rs`)** – High-speed, multi-threaded SHA-256 scanning.
- **YARA & ClamAV (`yara_integrations.c`)** – Signature-based malware detection.
- **eBPF real-time monitoring (`ebpf_monitor.bpf.c`)** – Tracks execution & file changes at the kernel level.
- **REST API Logging (`server.py`)** – Sends scan alerts to a web dashboard.
- **Signature Auto-Update (`update_signatures.sh`)** – Fetches latest malware definitions via Git.
- **Whitelist Support (`whitelist.txt`)** – Reduces false positives.

## Build & Deploy

- **Makefile** – Automates compilation & linking of all components.
- **Dashboard UI** – Web-based log visibility & reporting.


## Ideas

**Headless for quick and low-volume scans**
- Keep the file local and fast, **no prize for second place**.
**Agentless for VM and container-based deployments**
- Kubernetes audit logs or **Falco rules**, Legion could detect unusual processes or syscalls.
- API signature integration
- MLOp's .... yes pleaze. 



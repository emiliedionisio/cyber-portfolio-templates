# 🛰️ SOC Threat Detection Lab  

**Role:** SOC Analyst  
**Skills:** SIEM Configuration, Log Analysis, Threat Detection, Data Visualization  
**Tools:** Splunk Enterprise, Sysmon, Zeek, Windows Event Logs, Python SDK  

---

## 🧩 Overview  

This project demonstrates how to design and deploy a **Splunk-based SIEM environment** for real-time security monitoring and threat detection.  

The lab simulates a small enterprise network with multiple Windows endpoints and a network sensor (Zeek). Logs are ingested, normalized, and analyzed in Splunk to detect **brute-force attacks**, **C2 beaconing**, and **lateral movement patterns** using custom correlation searches.

---

## 🏗️ Architecture  

```plaintext
               +---------------------+
               |  Windows Endpoint 1 |
               |  Sysmon + Win Logs  |
               +---------+-----------+
                         |
                         v
               +---------------------+
               |  Zeek Sensor (IDS)  |
               |  Network Traffic     |
               +---------+-----------+
                         |
                         v
               +----------------------+
               |   Splunk Enterprise  |
               |   SIEM & Dashboard   |
               +----------------------+
                         |
                         v
               +----------------------+
               |   Analyst Workstation |
               |   Dashboards & IR     |
               +----------------------+

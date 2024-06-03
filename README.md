# Setting Up Azure Sentinel and Monitoring Failed RDP Logins from Around the World

## Description
This is a walkthrough for setting up an Azure virtual machine as a honeypot to monitor failed Remote Desktop Protocol (RDP) login attempts from around the world. The motivation is to gain experience with Security Information and Event Management (SIEM) systems like Azure Sentinel. The process involves ingesting failed RDP logs into Azure Sentinel, using PowerShell to extract geographic data from the attacker IPs, and visualizing the attacks on a world map within Azure Sentinel.

## Languages and Utilities Used
- PowerShell
- Azure Portal
- Azure Virtual Machines
- Azure Log Analytics Workspace 
- Azure Sentinel
- IPGeolocation API

## Environments Used
- Microsoft Azure Cloud
- Windows Virtual Machine 

## Walkthrough

### 1. Set up Azure Free Subscription
1. Visit https://azure.microsoft.com/en-us/free/
2. Click "Start free" and follow the signup process
3. Provide payment details (you won't be charged, it's for verification)
4. You'll get $200 in free credits to start

### 2. Create a Resource Group
1. Log into the Azure portal at https://portal.azure.com
2. Click "Create a resource" in the top left
3. Search for "Resource group" and click Create
4. Name it "HoneypotLab" and select your region
5. Click Review + Create, then Create

### 3. Create a Virtual Machine (VM) and Configure as Honeypot
1. In Azure portal search bar, type "Virtual machine"
2. Click Add > "Azure Virtual Machine"
3. Set options:
   - Name: "HoneypotVM"
   - Resource group: "HoneypotLab"
   - Region: (same as resource group)
   - Leave defaults for disk type, size
   - Create username and secure password
4. Click Review + Create, then Create
5. Once deployed, go to VM > Connect > RDP
6. Download RDP file, open to connect
7. In the VM:
   - Search "Windows Defender Firewall", turn Off all
   - Search "Windows Firewall", turn off all

### 4. Create a Log Analytics Workspace
1. In Azure, search "Log Analytics workspaces"
2. Click Add
3. Name it "HoneypotLogs"
4. Select "HoneypotLab" resource group, same region
5. Click OK

### 5. Connect VM to Log Analytics
1. Go to "HoneypotLogs" workspace
2. Under Settings > Virtual machines
3. Click Add, select "HoneypotVM"
4. Enable Log Analytics agent

### 6. Enable Azure Sentinel
1. Search "Sentinel" in Azure portal
2. Click Add
3. Select "HoneypotLogs" workspace

### 7. On VM, Download and Run Custom PowerShell Script
1. On VM desktop, open Notepad
2. Visit GitHub link in video description
3. Copy all PowerShell code into new file
4. Save as `LogExporter.ps1` on Desktop
5. Open PowerShell (search in Start menu)
6. Run: `Set-ExecutionPolicy Unrestricted`
7. Navigate: `cd desktop:`
8. Run script: `.\LogExporter.ps1`
9. Visit https://ipgeolocation.io, create account
10. Copy API key, paste into script variable

### 8. Create Custom Log in Log Analytics
1. Go to Log Analytics workspace
2. Click "Custom Logs" under "Workspace Data Sources"
3. Click "Add custom log"
4. Browse to `C:\ProgramData\failed_rdp.log` on VM
5. Extract fields:
   - latitude (numeric)
   - longitude (numeric)
   - country (text)
   - state (text)
   - sourceHost (text)
   - label (text)
   - timestamp (datetime)

### 9. Visualize Attacks in Sentinel Workbooks
1. In Azure Sentinel, click "Workbooks"
2. Add new workbook
3. Click Edit
4. Remove default tiles
5. Add > Query > Paste Kusto query:

FailedRDPwithGeo_CL
| where DestinationHostName_CF != "sample_host"
| project TimeGenerated, SourceHost_CF, Country_CF, Latitude_d, Longitude_d, Label_CF
| summarize count() by Country_CF, Latitude_d, Longitude_d, Label_CF

6. Set visualization to Map
7. Configure Size by `count_`
8. Save, close, refresh workbook

### 10. Monitor and Analyze
1. Leave VM running, LogExporter executing
2. Check Sentinel Workbook map periodically
3. Watch attacks appear from around the world!
4. Analyze:
- Usernames tried (admin, administrator, etc.)
- Attack source patterns (Asia, Russia, etc.)
- Attack frequency over time

## Remember to delete your "HoneypotLab" resource group in Azure when you're done to avoid using up your free credits!

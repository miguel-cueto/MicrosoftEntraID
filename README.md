# Setting up Azure Sentinel with a Vulnerable VM Honeypot

## Description
This guide provides a step-by-step walkthrough for setting up Azure Sentinel, a cloud-based Security Information and Event Management (SIEM) solution, along with a vulnerable virtual machine (VM) honeypot. The goal is to monitor and log failed Remote Desktop Protocol (RDP) login attempts from various IP addresses around the world and visualize the attack data on a map.

## Language and Utilities
- PowerShell
- Azure Portal
- Azure Sentinel
- Log Analytics Workspace
- ipgeolocation.io API

## Environments Used
- Microsoft Azure Cloud
- Windows Virtual Machine

## Program Walkthrough

### Step 1: Create an Azure Subscription
1. Go to the Azure portal (portal.azure.com) and create a new Azure subscription. You will receive $200 worth of free credits for the first month.

### Step 2: Create a Virtual Machine
1. In the Azure portal, navigate to "Virtual Machines" and click "Create."
2. Create a new resource group named "honeypot lab."
3. Name the virtual machine "honeypot" or "honeypot-vm."
4. Select the geographic region "West US 2."
5. Leave the default image and size settings.
6. Create a username and password for the VM, and remember these credentials.
7. Under "Networking," navigate to the "Network Security Group" and create a new one.
8. Remove the default inbound security rule and create a new one with the following settings:
  - Source: Any
  - Source port ranges: *
  - Destination: Any
  - Destination port ranges: *
  - Protocol: Any
  - Action: Allow
  - Priority: 100
  - Name: "danger-any-in"
9. Review and create the virtual machine.

### Step 3: Create a Log Analytics Workspace
1. In the Azure portal, navigate to "Log Analytics Workspaces" and create a new workspace.
2. Use the resource group "honeypot lab" and name the workspace "la-honeypot-1."
3. Select the region "West US 2."
4. Review and create the workspace.

### Step 4: Enable Log Collection
1. In the Azure Security Center, navigate to "Pricing & Settings."
2. Select the newly created Log Analytics workspace and turn on "Azure Defender."
3. Turn off "SQL servers" and save the settings.
4. Under "Data Collection," select "All Events" and save the settings.
5. In the Log Analytics workspace, connect the workspace to the virtual machine.

### Step 5: Set up Azure Sentinel
1. In the Azure portal, navigate to "Azure Sentinel" and create a new instance.
2. Select the Log Analytics workspace created earlier and add it to Azure Sentinel.

### Step 6: Disable Firewalls on the Virtual Machine
1. Log in to the virtual machine using Remote Desktop Protocol (RDP).
2. Open the Windows Defender Firewall and turn off the firewall for all profiles (Domain, Private, and Public).
3. From your local machine, ping the virtual machine's IP address to ensure it is accepting ICMP echo requests.

### Step 7: Download and Configure the PowerShell Script
1. Download the "Custom Security Log Exporter" PowerShell script from the provided GitHub link.
2. Open PowerShell on the virtual machine and paste the script content.
3. Save the script as "log-exporter.ps1" on the desktop.
4. Obtain an API key from ipgeolocation.io by creating a free account.
5. Replace the API key in the script with your own key.
6. Run the PowerShell script.

### Step 8: Create a Custom Log in Log Analytics
1. In the Log Analytics workspace, navigate to "Custom Logs" and add a new custom log.
2. Browse and select the "failed-rdp.log" file from your local machine's desktop.
3. Provide the collection path as "C:\ProgramData\failed_rdp.log" on the virtual machine.
4. Name the custom log "failed-rdp-with-geo."
5. Extract fields from the log data, such as latitude, longitude, country, and label.
6. Save the custom log configuration.

### Step 9: Visualize the Attack Data on a Map
1. In Azure Sentinel, navigate to "Workbooks" and create a new workbook.
2. Add a query widget and paste the provided query to display the failed RDP login attempts with geolocation data.
3. Add a map visualization and configure it to display the attack data using latitude and longitude or by country.
4. Customize the map settings and labels as desired.
5. Save the workbook as "failed-rdp-world-map."

### Step 10: Monitor and Visualize Attacks
1. Leave the virtual machine running and the PowerShell script executing.
2. Periodically refresh the map in Azure Sentinel to visualize the failed RDP login attempts from various IP addresses and countries.
3. Observe the attack patterns and the countries from which the attacks originate.

### Step 11: Clean Up Resources (Optional)
1. Once you have finished monitoring the attacks, navigate to the resource group in the Azure portal.
2. Delete the resource group to clean up all the resources created during this lab and avoid incurring additional costs.

Remember to replace any placeholders or variables with your specific values and adjust the instructions as needed based on your environment. Additionally, ensure you have the necessary permissions and follow best practices for security and resource management in Azure.

# Setting up Microsoft Sentinel with a Vulnerable VM Honeypot

## Description
This guide provides a step-by-step walkthrough for setting up Microsoft Sentinel, a cloud-based Security Information and Event Management (SIEM) solution, along with a vulnerable virtual machine (VM) honeypot. The goal is to monitor and log failed Remote Desktop Protocol (RDP) login attempts from various IP addresses around the world and visualize the attack data on a map.

## Language and Utilities
- PowerShell
- Azure Portal
- Microsoft Sentinel
- Log Analytics Workspace
- ipgeolocation.io API

## Environments Used
- Microsoft Azure Cloud
- Windows Virtual Machine

## Program Walkthrough

### Step 1: Create an Azure Subscription
1. Go to Azure (https://azure.microsoft.com/en-us/free/) and create a new Azure subscription. You will receive $200 worth of free credits for the first month.

<p align="center">
<img src="https://i.imgur.com/1JxWLpJ.png" height="80%" width="80%" alt="Azure"/>
<br />
<br />
  
### Step 2: Create a Virtual Machine
1. In the Azure portal (portal.azure.com), go to the search engine on the top navigate to "Virtual Machines" and click "Create" > click "Azure virtual machine."

<p align="center">
<img src="https://i.imgur.com/X2VZKTV.png" height="80%" width="80%" alt="Azure"/>
<br />
<br />
  
2. Create a new resource group named "honeypotlab"
3. Name the virtual machine "honeypot-vm."
4. Select the geographic region "West US 2" and availability zone "zone 2"

<p align="center">
<img src="https://i.imgur.com/UKcpGJA.png" height="80%" width="80%" alt="Azure"/>
<br />
<br />
  
5. Select the image "Windows 10 Pro, version 22H2 - x64 Gen 2."

<p align="center">
<img src="https://i.imgur.com/TtI8Z8A.png" height="80%" width="80%" alt="Azure"/>
<br />
<br />
  
6. Create a username and password for the VM, remember these credentials, and check the box under "Licensing" that reads "I confirm I have an eligible Windows 10/11 license with multi-tenant hosting rights" before clicking on "Next : Disk >" and "Next : Networking >"

<p align="center">
<img src="https://i.imgur.com/8ekpv7t.png" height="80%" width="80%" alt="Azure"/>
<br />
<br />
  
7. Under "Networking," navigate to the "NIC Network Security Group" and click Advanced

<p align="center">
<img src="https://i.imgur.com/SHIqtV3.png" height="80%" width="80%" alt="Azure"/>
<br />
<br />
  
8. Click on "Create new" under "Configure network security group
" and remove the default inbound security rule and create a new one with the following settings:
  - Source: Any
  - Source port ranges: *
  - Destination: Any
  - Destination port ranges: *
  - Protocol: Any
  - Action: Allow
  - Priority: 100
  - Name: "DANGER_ANY_IN"

<p align="center">
<img src="https://i.imgur.com/fzmFOx1.png" height="80%" width="80%" alt="Azure"/>
<br />
<br />
  
<p align="center">
<img src="https://i.imgur.com/FeXE8ps.png" height="80%" width="80%" alt="Azure"/>
<br />
<br />
    
<p align="center">
<img src="https://i.imgur.com/eVzMkVf.png" height="80%" width="80%" alt="Azure"/>
<br />
<br />
    
<p align="center">
<img src="https://i.imgur.com/DIydrmv.png" height="80%" width="80%" alt="Azure"/>
<br />
<br />

9. Review and create the virtual machine.
    
<p align="center">
<img src="https://i.imgur.com/oT9BVc5.png" height="80%" width="80%" alt="Azure"/>
<br />
<br />
  
### Step 3: Create a Log Analytics Workspace
1. In the Azure search engine, navigate to "Log Analytics Workspaces" and create a new workspace.    

<p align="center">
<img src="https://i.imgur.com/FYHau88.png" height="80%" width="80%" alt="Azure 55"/>
<br />
<br />
  
2. Use the resource group "Honeypotlab" and name the workspace "law-honeypot."
3. Select the region "West US 2."    

<p align="center">
<img src="https://i.imgur.com/mK72WWX.png" height="80%" width="80%" alt="Azure 56"/>
<br />
<br />
  
4. Review and create the workspace.

### Step 4: Enable Log Collection
1. In the Azure Search Engine go to "Microsoft Defender for Cloud", and navigate to "Environment settings" under Management on the left-hand side.
2. Select ">" next to Azure > Tenant Root Group > Azure Subscription 1 and click on "law-honeypot."

<p align="center">
<img src="https://i.imgur.com/YifLpEe.png" height="80%" width="80%" alt="Azure 58"/>
<br />
<br />
  
3. Turn on "Servers" and save the settings.

<p align="center">
<img src="https://i.imgur.com/YDSyNAY.png" height="80%" width="80%" alt="Azure 59"/>
<br />
<br />
  
4. Under "Data Collection," select "All Events" and save the settings.

<p align="center">
<img src="https://i.imgur.com/btVStNh.png" height="80%" width="80%" alt="Azure 60"/>
<br />
<br />
  
5. Use the Search Engine to go back to Log Analytics Workspace, connect the workspace "law-honeypot" > classic > virtual machines > "honeypot-vm" > and click Connect

<p align="center">
<img src="https://i.imgur.com/UZfzERz.png" height="80%" width="80%" alt="Azure 61"/>
<br />
<br />
  

### Step 5: Set up Azure Sentinel
1. In the Azure Search Engine, navigate to "Microsoft Sentinel" and create a new instance.

<p align="center">
<img src="https://i.imgur.com/ZKMKecX.png" height="80%" width="80%" alt="Azure 62"/>
<br />
<br />
  
2. Select the Log Analytics workspace created "law-honeypot" and click "Add"

<p align="center">
<img src="https://i.imgur.com/IqLLSeG.png" height="80%" width="80%" alt="Azure 63"/>
<br />
<br />
  

### Step 6: Disable Firewalls on the Virtual Machine
1. In the Azure Search Engine, navigate to "Virtual Machine" > "honeypot-vm" > copy the Public IP address and log into it using Remote Desktop Protocol (RDP).

<p align="center">
<img src="https://i.imgur.com/PpZQn0t.png" height="80%" width="80%" alt="Azure 64"/>
<br />
<br />
  
<p align="center">
<img src="https://i.imgur.com/0eF9KzE.png" height="80%" width="80%" alt="Azure 65"/>
<br />
<br />
  
2. Start menu > Remote Desktop Connection > paste the IP address > connect > use the username and password created initially > Click "Yes" on the certificate windows

<p align="center">
<img src="https://i.imgur.com/yByOqwW.png" height="80%" width="80%" alt="Azure 66"/>
<br />
<br />
  
3. In the VM set up toggle "no" on all privacy settings, press "yes" for networks, and start Microsoft Edge without your data

<p align="center">
<img src="https://i.imgur.com/YNGZg98.png" height="80%" width="80%" alt="Azure 67"/>
<br />
<br />
  
<p align="center">
<img src="https://i.imgur.com/jU7WItx.png" height="80%" width="80%" alt="Azure 68"/>
<br />
<br />
  
4. Open the Windows Defender Firewall (wf.msc) in the VM > click Windows Defender Firewall Properties and turn off the firewall for all profiles (Domain, Private, and Public).

<p align="center">
<img src="https://i.imgur.com/R3UArjv.png" height="80%" width="80%" alt="Azure 69"/>
<br />
<br />
  
<p align="center">
<img src="https://i.imgur.com/IuoA6EW.png" height="80%" width="80%" alt="Azure 70"/>
<br />
<br />
  
<p align="center">
<img src="https://i.imgur.com/bJkJicN.png" height="80%" width="80%" alt="Azure 71"/>
<br />
<br />
  
5. From your local machine, ping the virtual machine's IP address to ensure it is accepting ICMP echo requests.

### Step 7: Configure the PowerShell Script
1. Copy the  following script...

﻿# Get API key from here: https://ipgeolocation.io/
$API_KEY      = "d4600b4efdef42b39828f5155041a457"
$LOGFILE_NAME = "failed_rdp.log"
$LOGFILE_PATH = "C:\ProgramData\$($LOGFILE_NAME)"

# This filter will be used to filter failed RDP events from Windows Event Viewer
$XMLFilter = @'
<QueryList> 
   <Query Id="0" Path="Security">
         <Select Path="Security">
              *[System[(EventID='4625')]]
          </Select>
    </Query>
</QueryList> 
'@

<#
    This function creates a bunch of sample log files that will be used to train the
    Extract feature in Log Analytics workspace. If you don't have enough log files to
    "train" it, it will fail to extract certain fields for some reason -_-.
    We can avoid including these fake records on our map by filtering out all logs with
    a destination host of "samplehost"
#>
Function write-Sample-Log() {
    "latitude:47.91542,longitude:-120.60306,destinationhost:samplehost,username:fakeuser,sourcehost:24.16.97.222,state:Washington,country:United States,label:United States - 24.16.97.222,timestamp:2021-10-26 03:28:29" | Out-File $LOGFILE_PATH -Append -Encoding utf8
    "latitude:-22.90906,longitude:-47.06455,destinationhost:samplehost,username:lnwbaq,sourcehost:20.195.228.49,state:Sao Paulo,country:Brazil,label:Brazil - 20.195.228.49,timestamp:2021-10-26 05:46:20" | Out-File $LOGFILE_PATH -Append -Encoding utf8
    "latitude:52.37022,longitude:4.89517,destinationhost:samplehost,username:CSNYDER,sourcehost:89.248.165.74,state:North Holland,country:Netherlands,label:Netherlands - 89.248.165.74,timestamp:2021-10-26 06:12:56" | Out-File $LOGFILE_PATH -Append -Encoding utf8
    "latitude:40.71455,longitude:-74.00714,destinationhost:samplehost,username:ADMINISTRATOR,sourcehost:72.45.247.218,state:New York,country:United States,label:United States - 72.45.247.218,timestamp:2021-10-26 10:44:07" | Out-File $LOGFILE_PATH -Append -Encoding utf8
    "latitude:33.99762,longitude:-6.84737,destinationhost:samplehost,username:AZUREUSER,sourcehost:102.50.242.216,state:Rabat-Salé-Kénitra,country:Morocco,label:Morocco - 102.50.242.216,timestamp:2021-10-26 11:03:13" | Out-File $LOGFILE_PATH -Append -Encoding utf8
    "latitude:-5.32558,longitude:100.28595,destinationhost:samplehost,username:Test,sourcehost:42.1.62.34,state:Penang,country:Malaysia,label:Malaysia - 42.1.62.34,timestamp:2021-10-26 11:04:45" | Out-File $LOGFILE_PATH -Append -Encoding utf8
    "latitude:41.05722,longitude:28.84926,destinationhost:samplehost,username:AZUREUSER,sourcehost:176.235.196.111,state:Istanbul,country:Turkey,label:Turkey - 176.235.196.111,timestamp:2021-10-26 11:50:47" | Out-File $LOGFILE_PATH -Append -Encoding utf8
    "latitude:55.87925,longitude:37.54691,destinationhost:samplehost,username:Test,sourcehost:87.251.67.98,state:null,country:Russia,label:Russia - 87.251.67.98,timestamp:2021-10-26 12:13:45" | Out-File $LOGFILE_PATH -Append -Encoding utf8
    "latitude:52.37018,longitude:4.87324,destinationhost:samplehost,username:AZUREUSER,sourcehost:20.86.161.127,state:North Holland,country:Netherlands,label:Netherlands - 20.86.161.127,timestamp:2021-10-26 12:33:46" | Out-File $LOGFILE_PATH -Append -Encoding utf8
    "latitude:17.49163,longitude:-88.18704,destinationhost:samplehost,username:Test,sourcehost:45.227.254.8,state:null,country:Belize,label:Belize - 45.227.254.8,timestamp:2021-10-26 13:13:25" | Out-File $LOGFILE_PATH -Append -Encoding utf8
    "latitude:-55.88802,longitude:37.65136,destinationhost:samplehost,username:Test,sourcehost:94.232.47.130,state:Central Federal District,country:Russia,label:Russia - 94.232.47.130,timestamp:2021-10-26 14:25:33" | Out-File $LOGFILE_PATH -Append -Encoding utf8
}

# This block of code will create the log file if it doesn't already exist
if ((Test-Path $LOGFILE_PATH) -eq $false) {
    New-Item -ItemType File -Path $LOGFILE_PATH
    write-Sample-Log
}

# Infinite Loop that keeps checking the Event Viewer logs.
while ($true)
{
    
    Start-Sleep -Seconds 1
    # This retrieves events from Windows EVent Viewer based on the filter
    $events = Get-WinEvent -FilterXml $XMLFilter -ErrorAction SilentlyContinue
    if ($Error) {
        #Write-Host "No Failed Logons found. Re-run script when a login has failed."
    }

    # Step through each event collected, get geolocation
    #    for the IP Address, and add new events to the custom log
    foreach ($event in $events) {


        # $event.properties[19] is the source IP address of the failed logon
        # This if-statement will proceed if the IP address exists (>= 5 is arbitrary, just saying if it's not empty)
        if ($event.properties[19].Value.Length -ge 5) {

            # Pick out fields from the event. These will be inserted into our new custom log
            $timestamp = $event.TimeCreated
            $year = $event.TimeCreated.Year

            $month = $event.TimeCreated.Month
            if ("$($event.TimeCreated.Month)".Length -eq 1) {
                $month = "0$($event.TimeCreated.Month)"
            }

            $day = $event.TimeCreated.Day
            if ("$($event.TimeCreated.Day)".Length -eq 1) {
                $day = "0$($event.TimeCreated.Day)"
            }
            
            $hour = $event.TimeCreated.Hour
            if ("$($event.TimeCreated.Hour)".Length -eq 1) {
                $hour = "0$($event.TimeCreated.Hour)"
            }

            $minute = $event.TimeCreated.Minute
            if ("$($event.TimeCreated.Minute)".Length -eq 1) {
                $minute = "0$($event.TimeCreated.Minute)"
            }


            $second = $event.TimeCreated.Second
            if ("$($event.TimeCreated.Second)".Length -eq 1) {
                $second = "0$($event.TimeCreated.Second)"
            }

            $timestamp = "$($year)-$($month)-$($day) $($hour):$($minute):$($second)"
            $eventId = $event.Id
            $destinationHost = $event.MachineName# Workstation Name (Destination)
            $username = $event.properties[5].Value # Account Name (Attempted Logon)
            $sourceHost = $event.properties[11].Value # Workstation Name (Source)
            $sourceIp = $event.properties[19].Value # IP Address
        

            # Get the current contents of the Log file!
            $log_contents = Get-Content -Path $LOGFILE_PATH

            # Do not write to the log file if the log already exists.
            if (-Not ($log_contents -match "$($timestamp)") -or ($log_contents.Length -eq 0)) {
            
                # Announce the gathering of geolocation data and pause for a second as to not rate-limit the API
                #Write-Host "Getting Latitude and Longitude from IP Address and writing to log" -ForegroundColor Yellow -BackgroundColor Black
                Start-Sleep -Seconds 1

                # Make web request to the geolocation API
                # For more info: https://ipgeolocation.io/documentation/ip-geolocation-api.html
                $API_ENDPOINT = "https://api.ipgeolocation.io/ipgeo?apiKey=$($API_KEY)&ip=$($sourceIp)"
                $response = Invoke-WebRequest -UseBasicParsing -Uri $API_ENDPOINT

                # Pull Data from the API response, and store them in variables
                $responseData = $response.Content | ConvertFrom-Json
                $latitude = $responseData.latitude
                $longitude = $responseData.longitude
                $state_prov = $responseData.state_prov
                if ($state_prov -eq "") { $state_prov = "null" }
                $country = $responseData.country_name
                if ($country -eq "") {$country -eq "null"}

                # Write all gathered data to the custom log file. It will look something like this:
                #
                "latitude:$($latitude),longitude:$($longitude),destinationhost:$($destinationHost),username:$($username),sourcehost:$($sourceIp),state:$($state_prov), country:$($country),label:$($country) - $($sourceIp),timestamp:$($timestamp)" | Out-File $LOGFILE_PATH -Append -Encoding utf8

                Write-Host -BackgroundColor Black -ForegroundColor Magenta "latitude:$($latitude),longitude:$($longitude),destinationhost:$($destinationHost),username:$($username),sourcehost:$($sourceIp),state:$($state_prov),label:$($country) - $($sourceIp),timestamp:$($timestamp)"
            }
            else {
                # Entry already exists in custom log file. Do nothing, optionally, remove the # from the line below for output
                # Write-Host "Event already exists in the custom log. Skipping." -ForegroundColor Gray -BackgroundColor Black
            }
        }
    }
}
  
<p align="center">
<img src="https://i.imgur.com/lXPakqU.png" height="80%" width="80%" alt="Azure 72"/>
<br />
<br />
  
4. Open PowerShell ISE on the virtual machine by clicking the Start Icon > Windows Powershell > Windows Powershell ISE > More > Run as Administrator and paste "Set-ExecutionPolicy Unrestricted" click "Yes to all" then the script content.  

5. Save the script as "Log-Exporter.ps1" on the desktop.  

<p align="center">
<img src="https://i.imgur.com/XkASuYV.png" height="80%" width="80%" alt="Azure 73"/>
<br />
<br />
  
6. Obtain an API key from ipgeolocation.io by creating a free account.
7. Replace the API key in the script with your own key.
8. Run the PowerShell script.

<p align="center">
<img src="https://i.imgur.com/EXedgTv.png" height="80%" width="80%" alt="Azure 74"/>
<br />
<br />
  
### Step 8: Create a Custom Log in Log Analytics
1. Go to the VM and press Window + R > C:\ProgramData\ > failed.rdp > copy the contents
2. Go back to your PC Start Menu > Notepad > Paste the contents and save as "failed_rdp.log" on your Desktop

<p align="center">
<img src="https://i.imgur.com/QpLeYuo.png" width="80%" alt="Azure 75"/>
<br />
<br />
  
3. In the Log Analytics workspace, click on "law-honeypot" > settings > tables > create > new custom log (MMA based)

<p align="center">
<img src="https://i.imgur.com/E1YidlU.png" height="80%" width="80%" alt="Azure 76"/>
<br />
<br />
  
<p align="center">
<img src="https://i.imgur.com/mHSIlNf.png" height="80%" width="80%" alt="Azure 77"/>
<br />
<br />

4. Browse and select the "failed_rdp.log" file from your local machine's desktop and click next  

<p align="center">
<img src="https://i.imgur.com/Bq17Zk6.png" height="80%" width="80%" alt="Azure 78"/>
<br />
<br />
  
5. In "Collection Path" choose Windows for type and "C:\ProgramData\failed_rdp.log" for path, click next  

<p align="center">
<img src="https://i.imgur.com/s7i1jmD.png" height="80%" width="80%" alt="Azure 79"/>
<br />
<br />
  
6. In "Details" copy and paste "FAILED_RDP_WITH_GEO" in custom log names > click next > create  

<p align="center">
<img src="https://i.imgur.com/BBv2goU.png" height="80%" width="80%" alt="Azure 80"/>
<br />
<br />
    
<p align="center">
<img src="https://i.imgur.com/AxNa2bV.png" height="80%" width="80%" alt="Azure 81"/>
<br />
<br />
  
7. In the Log Analytics workspace, click on "law-honeypot" > logs > and copy and paste the following:

FAILED_RDP_WITH_GEO_CL 
| extend username = extract(@"username:([^,]+)", 1, RawData),
         timestamp = extract(@"timestamp:([^,]+)", 1, RawData),
         latitude = extract(@"latitude:([^,]+)", 1, RawData),
         longitude = extract(@"longitude:([^,]+)", 1, RawData),
         sourcehost = extract(@"sourcehost:([^,]+)", 1, RawData),
         state = extract(@"state:([^,]+)", 1, RawData),
         label = extract(@"label:([^,]+)", 1, RawData),
         destination = extract(@"destinationhost:([^,]+)", 1, RawData),
         country = extract(@"country:([^,]+)", 1, RawData)
| where destination != "samplehost"
| where sourcehost != ""
| summarize event_count=count() by latitude, longitude, sourcehost, label, destination, country

8. Click "Run"  

<p align="center">
<img src="https://i.imgur.com/qPfQY2e.png" height="80%" width="80%" alt="Azure 84"/>
<br />
<br />

### Step 9: Visualize the Attack Data on a Map
1. In Microsoft Sentinel, click on "law-honeypot" > Threat Management > Workbooks > Add Workbook > Edit

<p align="center">
<img src="https://i.imgur.com/tQkO6XQ.png" height="80%" width="80%" alt="Azure 85"/>
<br />
<br />


<p align="center">
<img src="https://i.imgur.com/aHFMfdE.png" height="80%" width="80%" alt="Azure 86"/>
<br />
<br />


2. Remove the 2 widgets that come with the workbook.

<p align="center">
<img src="https://i.imgur.com/7kZW3jc.png" height="80%" width="80%" alt="Azure 87"/>
<br />
<br />


3. Add a query widget and paste the following ...

FAILED_RDP_WITH_GEO_CL 
| extend username = extract(@"username:([^,]+)", 1, RawData),
         timestamp = extract(@"timestamp:([^,]+)", 1, RawData),
         latitude = extract(@"latitude:([^,]+)", 1, RawData),
         longitude = extract(@"longitude:([^,]+)", 1, RawData),
         sourcehost = extract(@"sourcehost:([^,]+)", 1, RawData),
         state = extract(@"state:([^,]+)", 1, RawData),
         label = extract(@"label:([^,]+)", 1, RawData),
         destination = extract(@"destinationhost:([^,]+)", 1, RawData),
         country = extract(@"country:([^,]+)", 1, RawData)
| where destination != "samplehost"
| where sourcehost != ""
| summarize event_count=count() by latitude, longitude, sourcehost, label, destination, country

<p align="center">
<img src="https://i.imgur.com/28p9VBc.png" height="80%" width="80%" alt="Azure 88"/>
<br />
<br />


<p align="center">
<img src="https://i.imgur.com/21f2v4G.png" height="80%" width="80%" alt="Azure 89"/>
<br />
<br />


4. Run Quiry > change Visualization to "Map."  The provided query will display the failed RDP login attempts with geolocation data.

<p align="center">
<img src="https://i.imgur.com/Q4OouEv.png" height="80%" width="80%" alt="Azure 90"/>
<br />
<br />


<p align="center">
<img src="https://i.imgur.com/V1zQnUN.png" height="80%" width="80%" alt="Azure 91"/>
<br />
<br />


5. Save the workbook as "Failed RDP World Map" and change the location to "(US) West US 2"

<p align="center">
<img src="https://i.imgur.com/3l1Y5nF.png" height="80%" width="80%" alt="Azure 93"/>
<br />
<br />

<p align="center">
<img src="https://i.imgur.com/bTQMNuo.png" height="80%" width="80%" alt="Azure 94"/>
<br />
<br />

6. Turn auto refresh to 5 minutes.

<p align="center">
<img src="https://i.imgur.com/Oz69RNZ.png" height="80%" width="80%" alt="Azure 95"/>
<br />
<br />

<p align="center">
<img src="https://i.imgur.com/3IykdAZ.png" height="80%" width="80%" alt="Azure 96"/>
<br />
<br />
  
### Step 10: Monitor and Visualize Attacks
1. Leave the virtual machine running and the PowerShell script executing.
2. Periodically refresh the map in Microsoft Sentinel to visualize the failed RDP login attempts from various IP addresses and countries.

<p align="center">
<img src="https://i.imgur.com/q0uTDpn.png" height="80%" width="80%" alt="Azure 97"/>
<br />
<br />
  
3. Observe the attack patterns and the countries from which the attacks originate.

<p align="center">
<img src="https://i.imgur.com/EX2JCoS.png" height="80%" width="80%" alt="Azure 98"/>
<br />
<br />
  
### Step 11: Clean Up Resources (Optional)
1. Go to the  Azure portal > Find your resource group (honeypotlab) > Click on Delete resource group. This will delete all resources within the group, including the VM and Log Analytics workspace if you haven’t deleted them individually.

<p align="center">
<img src="https://i.imgur.com/ahgyQTN.png" height="80%" width="80%" alt="Azure 100"/>
<br />
<br />
  
<p align="center">
<img src="https://i.imgur.com/MvQXIYh.png" height="80%" width="80%" alt="Azure 101"/>
<br />
<br />
  
2. Check the box "Apply force delete for selected Virtual machines and Virtual machine scale sets" and write the name of the resource group "honeypotlab" then click "Delete."

<p align="center">
<img src="https://i.imgur.com/nSFtcZi.png" height="80%" width="80%" alt="Azure 102"/>
<br />
<br />
  
4. Ensure there are no other resources under your subscription that might be incurring charges by going to Cost Management + Billing in the Azure portal to review your usage and ensure no unexpected charges.

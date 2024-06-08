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
1. Go to Azure (https://azure.microsoft.com/en-us/free/) and create a new Azure subscription. You will receive $200 worth of free credits for the first month.

### Step 2: Create a Virtual Machine
1. In the Azure portal (portal.azure.com), go to the search engine on the top navigate to "Virtual Machines" and click "Create."
2. Create a new resource group named "honeypotlab"
3. Name the virtual machine "honeypot-vm."
4. Select the geographic region "West US 3."
5. Leave the default image and size settings.
6. Create a username and password for the VM, and remember these credentials.
7. Under "Networking," navigate to the "NIC Network Security Group" click advanced
8. Remove the default inbound security rule and create a new one with the following settings:
  - Source: Any
  - Source port ranges: *
  - Destination: Any
  - Destination port ranges: *
  - Protocol: Any
  - Action: Allow
  - Priority: 100
  - Name: "DANGER_ANY_IN"
9. Review and create the virtual machine.

### Step 3: Create a Log Analytics Workspace
1. In the Azure search engine, navigate to "Log Analytics Workspaces" and create a new workspace.
2. Use the resource group "Honeypotlab" and name the workspace "law-honeypot1."
3. Select the region "West US 2."
4. Review and create the workspace.

### Step 4: Enable Log Collection
1. In the Azure Search Engine go to Security Center, navigate to "Pricing & Settings."
2. Select the newly created Log Analytics workspace "law-honeypot1" and turn on "Azure Defender."
3. Turn off "SQL servers" and save the settings.
4. Under "Data Collection," select "All Events" and save the settings.
5. Use the Search Engine to go back to Log Analytics Workspace, connect the workspace "law-honeypot1" > virtual machine > "honeypot-vm" > and click Connect

### Step 5: Set up Azure Sentinel
1. In the Azure Search Engine, navigate to "Azure Sentinel" and create a new instance.
2. Select the Log Analytics workspace created "law-honeypot1" and add it to Azure Sentinel.

### Step 6: Disable Firewalls on the Virtual Machine
1. In the Azure Search Engine, navigate to "Virtual Machine" > "honeypot-vm" > copy the Public IP address and log into it using Remote Desktop Protocol (RDP).
2. Start menu > Remote Desktop Connection > paste the IP address > connect > use the username and password created initially.
3. In the VM set up Microsoft Edge
4. Open the Windows Defender Firewall in the VM and turn off the firewall for all profiles (Domain, Private, and Public).
5. From your local machine, ping the virtual machine's IP address to ensure it is accepting ICMP echo requests.

### Step 7: Configure the PowerShell Script
1. Copy the  following scrip ...

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

4. Open PowerShell ISE on the virtual machine and paste the script content.
5. Save the script as "Log-Exporter.ps1" on the desktop.
6. Obtain an API key from ipgeolocation.io by creating a free account.
7. Replace the API key in the script with your own key.
8. Run the PowerShell script.

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

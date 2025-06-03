# Potential-Impossible-Travel
would be suspect.
KQL Analysis Query Spoiler
// Highlight to show query 👇
// Investigate Potential Impossible Travel Instances
let TargetUserPrincipalName = "josh.madakor@gmail.com"; // Change to your target user (UserPrincipalName)
let TimePeriodThreshold = timespan(7d); // Change to how far back you want to look
SigninLogs
| where TimeGenerated > ago(TimePeriodThreshold)
| where UserPrincipalName == TargetUserPrincipalName
| project TimeGenerated, UserPrincipalName, City = tostring(parse_json(LocationDetails).city), State = tostring(parse_json(LocationDetails).state), Country = tostring(parse_json(LocationDetails).countryOrRegion)
| order by TimeGenerated desc



Observe the different Users (UserPrincipalNames) logon patterns and take notes
josh.madakor@gmail.com logged in from x and y within Z time period: suspect
arisa_lognpacific@lognpacific.com logged in from a and b within C time period: normal
etc.
Containment, Eradication, and Recovery
Isolate affected systems to prevent further damage.
In real life, depending on corporate policy and evidence, you might immediately disable the account in Entra ID (Azure Active Directory) and contact the user or the user’s manager to investigate.
It was determined that the alert was a TRUE POSITIVE. User ___ and logged into __ and __ within an __ day time period, which should not be possible.
The user's account was disabled and management contacted.
Remove the threat and restore systems to normal.
There is currently no threat to remove, further action may be taken pending a decision from management.
If the logon behavior was unusual, account compromise may be possible.
Pivot to see what other activity the user has been doing. For example, you can look in the AzureActivity log:
AzureActivity
| where tostring(parse_json(Claims)["http://schemas.microsoft.com/identity/claims/objectidentifier"]) == "<azure user id/guid>"
Post-Incident Activities
Update policies and tools to prevent recurrence.
You could do something like creating a geo-fencing policy within azure that prevents logins outside of certain regions. You can’t do this in our environment, but it’s something to keep in mind.
Document findings and lessons learned.
Record your notes within the incident.
Closure
Review and confirm incident resolution.
Review/observe your notes for the incident.
Finalize reporting and close the case.
Close out the Incident within Sentinel as a “Benign Positive” (or whatever it was in your case)
Part 4: Cleanup (BE EXTREMELY CAREFUL HERE)
In Sentinel → Threat Management → Incidents, filter for closed incidents and delete YOUR incident
In Sentinel → Configuration → Analytics, delete YOUR analytics rule.
Be extremely careful to only delete YOUR Incident and Analytics Rule. Do not screw this up and delete someone else's, because it’s possible. Search by your name to narrow them down if you have to.
—----

Detection Analysis
It was observe that four accounts had been flagged for potential impossible travel:

61f8b2dfc90aec741829201cdab353f99fcc3206d560235571bc8f81b0eb1b79@lognpacific.com
 db5cdbb2-fc04-467a-8ca3-e6a068ceef6a
 304fab51-34c9-4fe7-9934-6dd4accaefad
 C090ec75791042b65f72a10ef481dd22663a85817aecf6ba324b288fc1a78659

—------

Used the following query to inspect detailed login information for both account:

// Highlight to show query 👇
// Investigate Potential Impossible Travel Instances
let TargetUserPrincipalName = "mu-mde-test"; // Change to your target user (UserPrincipalName)
let TimePeriodThreshold = timespan(7d); // Change to how far back you want to look
SigninLogs
| where TimeGenerated > ago(TimePeriodThreshold)
| where UserPrincipalName == TargetUserPrincipalName
| project TimeGenerated, UserPrincipalName, City = tostring(parse_json(LocationDetails).city), State = tostring(parse_json(LocationDetails).state), Country = tostring(parse_json(LocationDetails).countryOrRegion)
| order by TimeGenerated desc

—-------

Observed first account (josh.madakor@gmail.com ) nothing really alerming all login withion a 3 hours train ride from each other within the same country: 

– same thing with the second (josh.madakor2_gmail@lognpacific.com) musas logged in from x and y within 2 time period : suspect Musas logged in from A and B within C time period: 
     
                  CONTAINMENT ERADICATION and RECOVERY:
 It was determined that the alert was a TRUE Benign. User Musa has login to Tokyo and Osaka within 3 hours time period which is not uncommon.
The user account was left intact due to expected behavior (not disabled)
                
                POST-INCIDENT ACTIVITIES:
I explored the option of implementing geofencing policies  to prevent login from outside the country.



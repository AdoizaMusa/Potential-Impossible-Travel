Impossible Travel Investigation: KQL Analysis
Detection Analysis
Four accounts were flagged for potential impossible travel:

61f8b2dfc90aec741829201cdab353f99fcc3206d560235571bc8f81b0eb1b79@lognpacific.com

db5cdbb2-fc04-467a-8ca3-e6a068ceef6a

304fab51-34c9-4fe7-9934-6dd4accaefad

C090ec75791042b65f72a10ef481dd22663a85817aecf6ba324b288fc1a78659

KQL Query: Investigate Potential Impossible Travel Instances
kql
Copy
Edit
// Investigate Potential Impossible Travel Instances
let TargetUserPrincipalName = "josh.madakor@gmail.com"; // Change to your target user (UserPrincipalName)
let TimePeriodThreshold = timespan(7d); // Change to how far back you want to look
SigninLogs
| where TimeGenerated > ago(TimePeriodThreshold)
| where UserPrincipalName == TargetUserPrincipalName
| project TimeGenerated,
          UserPrincipalName,
          City = tostring(parse_json(LocationDetails).city),
          State = tostring(parse_json(LocationDetails).state),
          Country = tostring(parse_json(LocationDetails).countryOrRegion)
| order by TimeGenerated desc
Observations
User: josh.madakor@gmail.com
Activity: Logged in from locations X and Y within Z time period — Suspect

User: arisa_lognpacific@lognpacific.com
Activity: Logged in from locations A and B within C time period — Normal

User: josh.madakor2_gmail@lognpacific.com
Activity: Logged in from locations X and Y within 2-hour time period — Suspect

User: musas
Activity: Logged in from Tokyo and Osaka within 3-hour time period — Benign

Containment, Eradication, and Recovery
Immediate Action: Isolated affected systems to prevent further damage.

Account Status: Determined alert was a TRUE POSITIVE for josh.madakor@gmail.com. The user logged into two geographically distant locations within an impossible time frame.

Remediation: User's account was disabled, and management was contacted for further investigation.

Post-Incident Activities
Policy Review: Explored implementing geo-fencing policies within Azure to prevent logins from outside designated regions.

Documentation: Recorded findings and lessons learned within the incident report.

Closure
Resolution Confirmation: Reviewed and confirmed incident resolution.

Reporting: Finalized reporting and closed the case.

Sentinel Update: Closed out the incident within Sentinel as a "Benign Positive" (or appropriate classification).

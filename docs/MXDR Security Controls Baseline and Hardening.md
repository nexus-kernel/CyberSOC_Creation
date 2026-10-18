# MXDR Security Controls: Foundational and Defense in Depth

Oct 9, 2026 · @Scott Bochelen

## Purpose and placement rules

Foundational controls are configured and verified before an environment exits build. Defense in depth controls layer on top of them and are sequenced with the client after build as the What comes next roadmap. Each pillar holds five of each, matching the pillar slides. Foundational controls score two points against one for defense in depth, so every pillar is graded out of 15. E means enforced on 90 percent or more of in-scope resources, P means 50 to 89 percent and N means under 50 percent.

A control is **foundational** when all three of these hold:

1. Other controls in the pillar depend on it.
2. It applies to every client in scope of the service.
3. Atmosera can deliver it inside the build window.

A control is **defense in depth** when any one of these is true:

- It needs application or dependency testing that only the client can perform.
- It needs a maintenance window, a reboot or a redeployment.
- It changes network or directory architecture.
- It needs licensing or recurring cost beyond the service agreement.
- It depends on tuning against the environment's own operating history.

Three working rules apply during build:

- Foundational controls are switched on directly, with no report-only stage. A review of the last 30 days of sign-in and resource evidence names every affected account and resource first, and each one is fixed or excluded with a documented reason.
- Controls that cannot be undone, such as Key Vault purge protection, and controls that change sign-in for every user are approved by the client at build kickoff.
- Resources the build deploys itself, such as the Sentinel workspace, playbooks, automation accounts and key vaults, meet every control in both tiers from the day they are created.

## Foundational controls

Twenty-seven foundational controls follow the pillar slides, five per pillar except network and boundary, which holds six since Oct 12, 2026, when encryption in transit on published web apps moved here from defense in depth, and detection and response, which holds six since Oct 16, 2026, when analytics rules and threat intelligence ingestion moved here and Defender for Identity moved to defense in depth. Each exits build at E, enforced on 90 percent or more of in-scope resources, with every remaining resource recorded as a documented exception. A foundational control that later reads P or N is reported as drift with a fix date. Since Oct 12, 2026 drift is shown on the posture slide and goes first in the roadmap's Now column as Atmosera's fix, ahead of the client-sequenced defense in depth work.

### Identity and access, SOC 2 CC6.1, CC6.2, CC6.3

| Foundational control | How the build delivers it | Measures |
| --- | --- | --- |
| Multifactor authentication required for all users | ATMO-MXDR-CA-MFA-ALLUSERS and ATMO-MXDR-CA-MFA-ADMIN | IA.1, IA.1-ADMINPORTAL |
| Location-based sign-in access controls enforced through Conditional Access | ATMO-MXDR-CA-BLOCK-LOCATION, blocking sign-ins from outside the countries and named networks the client approves at kickoff, for all users | IA.4-LOCATION |
| Legacy and high-risk authentication protocols blocked | ATMO-MXDR-CA-BLOCK-LEGACY and ATMO-MXDR-CA-BLOCK-DEVICECODE | IA.3, IA.3-DEVICECODE |
| Privileged role assignments governed and reviewed | Standing Entra directory role and Azure Owner assignments inventoried and reviewed with the client before exit | IA.10 |
| Anti-phishing policy applied to every mailbox | The Microsoft default anti-phishing policy enabled, which every mailbox falls under with spoof intelligence on | IA.9 |

### Endpoint and workload, SOC 2 CC6.8, CC7.1

| Foundational control | How the build delivers it | Measures |
| --- | --- | --- |
| Endpoint detection and response deployed across the fleet | Defender for Endpoint onboarding for every eligible device, and Defender for Servers with the endpoint integration on every subscription | EW.1 |
| Anti-malware in active mode with real-time and cloud-delivered protection | Defender Antivirus policy through Intune, Group Policy or security settings management | EW.3 |
| Tamper protection enforced so agents cannot be disabled | Tenant-wide tamper protection in Defender for Endpoint | EW.8 |
| Host firewall enforced centrally through endpoint policy | All firewall profiles held on through endpoint policy, with existing rules left in place | EW.9 |
| OS and Azure VM extension findings remediated on cadence | Patch and extension cadence agreed at kickoff and tracked against Defender for Cloud system update findings | EW.10 |

### Network and boundary, SOC 2 CC6.6, CC6.1

| Foundational control | How the build delivers it | Measures |
| --- | --- | --- |
| No management ports exposed directly to the internet | Inbound RDP and SSH from the internet removed from network security groups, with Bastion or just-in-time access in their place | NB.7 |
| Legacy and plaintext network protocols disabled | Secure transfer and TLS 1.2 on storage, TLS 1.2 on Azure SQL, and SMBv1 off through endpoint policy | DP.1, NB.6 |
| Anonymous host and share access restricted | Anonymous blob access disabled after a check that no container allows public read, and anonymous share access restricted through endpoint policy | DP.1 |
| App Service web apps refuse TLS below 1.2 | Minimum TLS 1.2 on every App Service and Function App configuration, the platform default for new apps. App Service rejects TLS 1.0 and 1.1 from May 31, 2027 regardless | NB.5 |
| Egress and DNS monitored for tunneling and command traffic | Defender for Endpoint network protection, Defender for Cloud DNS alerts and Sentinel rules for tunneling and beaconing | NB.8 |
| Encryption in transit enforced on published web apps | HTTPS only on every App Service and Function App, switched on after the 30-day review confirms no caller still uses plain HTTP | NB.4 |

### Data protection, SOC 2 CC6.7, C1.1, C1.2

| Foundational control | How the build delivers it | Measures |
| --- | --- | --- |
| Storage and managed disks encrypted with platform keys | Platform default, verified and reported as evidence | DP.3 |
| Secret and key stores protected against deletion and purge | Soft delete is a platform default. Purge protection is enabled on every vault after client approval, since it cannot be turned off | DP.2 |
| Mail and collaboration protected by threat protection | Safe Links on mail, Teams and Office, and Safe Attachments set to Block or Dynamic Delivery | IA.9-SAFELINKS, IA.9-SAFEATTACH |
| Malicious mail removed from mailboxes after delivery | Zero-hour auto purge left on for malware, phishing and high confidence phishing | DP.7 |
| Data loss prevention enforced across mail and endpoint | Purview data loss prevention policies built to what the client's current licensing supports. Items that need more licensing are handed over as a follow-up once the license is acquired, and items the client declines are noted in the SOW and shown as not in scope | DP.8 |

### Detection and response, SOC 2 CC7.2, CC7.3, CC7.4

| Foundational control | How the build delivers it | Measures |
| --- | --- | --- |
| Security telemetry centrally collected and retained | Sentinel workspace with its tenant connectors, plus the ATMO-MXDR-DIAG-TOSENT logging initiative | DR.6-INITIATIVE |
| Cloud workload protection enabled across the resource estate | Every Defender for Cloud plan that has matching resources in the client environment, enabled on every subscription | DR.2 |
| Endpoint detection sensor reporting on Azure virtual machines | Sensor health review in the final build week on every onboarded Azure virtual machine, with inactive sensors fixed or explained. Workstations and network devices such as Palo Alto, Meraki, Fortinet and SonicWall firewalls are not part of this measure | EW.1 |
| Every alert triaged to a documented disposition | SOC triage that closes every incident with a classification and a closing note | DR.10 |
| Analytics rules enabled in every Sentinel workspace | The Atmosera standard analytics rule set, deployed and enabled in each Sentinel workspace at build | DR.9 |
| Threat intelligence indicators ingested tenant-wide | Threat intelligence ingestion switched on at build, so indicators are available for matching in the workspace | DR.7 |

Analytics rules and threat intelligence ingestion moved here from defense in depth on Oct 16, 2026. Their rows grade what the build delivers. DR.9 reads In force when every Sentinel workspace in scope has at least one enabled analytics rule. Atmosera's rules carry no naming convention, so the evidence cannot tell the standard set from other rules, and DR.9 does not grade the standard set itself. The count of enabled rules is context only, so rules disabled while tuning never create a gap. Tuning the rules against the environment's own operating history, and blocking on matched indicators, are not delivered at build, so they are not graded by DR.9 or DR.7 and stay out of scope of the grade.

## Conditional Access foundation

Five ATMO-MXDR policies deliver the identity foundation. They are created On, with no report-only stage, after a review of the last 30 days of sign-ins names every affected account. Each needs Entra ID P1 and two emergency access accounts excluded from all five. Clients without P1 fall back to security defaults, covered below.

| Setting | ATMO-MXDR-CA-BLOCK-LEGACY | ATMO-MXDR-CA-BLOCK-DEVICECODE | ATMO-MXDR-CA-MFA-ADMIN | ATMO-MXDR-CA-MFA-ALLUSERS | ATMO-MXDR-CA-BLOCK-LOCATION |
| --- | --- | --- | --- | --- | --- |
| Foundational control | Legacy and high-risk authentication protocols blocked | Legacy and high-risk authentication protocols blocked | Multifactor authentication required for all users | Multifactor authentication required for all users | Location-based sign-in access controls enforced through Conditional Access |
| Measure ID | IA.3 | IA.3-DEVICECODE | IA.1-ADMINPORTAL | IA.1 | IA.4-LOCATION |
| Users included | All users | All users | All users | All users | All users |
| Users excluded | Emergency access accounts | Emergency access accounts, plus a group for approved device code devices | Emergency access accounts | Emergency access accounts, plus documented service accounts until they move to workload identities | Emergency access accounts, plus a travel exception group with time-bound membership |
| Target resources | All resources | All resources, excluding Device Registration Service where device code is used to register devices | Microsoft Admin Portals | All resources | All resources |
| Condition | Client apps set to Exchange ActiveSync clients and Other clients | Authentication flows set to Device code flow | None | None | Locations set to Any location, excluding the countries and named networks the client approves at kickoff |
| Grant | Block access | Block access | Require authentication strength Multifactor authentication | Require authentication strength Multifactor authentication | Block access |
| Pre-enforcement check | Sign-ins from legacy client apps, mainly service accounts using SMTP AUTH, POP or IMAP | Sign-ins with the Authentication protocol value Device code | Admin portal sign-ins from accounts with no registered MFA method | Users with no registered MFA method, and user accounts that only sign in non-interactively | Successful sign-ins from countries outside the approved list, with the accounts and applications that made them |

**Measure IDs.** The three new measures sit under the control they roll up into and follow the existing IA.9-SAFELINKS pattern, so they cannot collide with IA numbers already in use.

| ID | Measure | Reads as |
| --- | --- | --- |
| IA.3 | Legacy protocol sign-ins in the last 30 days, with the attempts Conditional Access stopped (error 53003) and the sign-ins that succeeded | In force when an enabled block policy or security defaults block legacy authentication. Without a policy inventory, In force only when Conditional Access blocks are recorded and no sign-in succeeded, Not in force when one succeeded, otherwise N/A. Attempts that fail without a Conditional Access block are never counted as blocked |
| IA.3-DEVICECODE | Device code flow sign-ins in the last 30 days, outside the approved device group | In force when the block policy is On. Without a policy inventory, the same rule as IA.3 |
| IA.1-ADMINPORTAL | Successful sign-ins to Microsoft Admin Portals in the last 30 days that satisfied MFA | A count against all admin portal sign-ins, like IA.1 |
| IA.4-LOCATION | Enabled Conditional Access policies with a country or named location condition that block access or require MFA, read from the raw policies (IA.8-POLICIES) | In force when one covers all users and all resources. A scoped or report-only policy reads Not in force. A grant of MFA by location also counts, so a client that steps up sign-ins outside trusted networks rather than blocking them still reads In force |

**Why a separate admin portal policy.** It targets all users rather than the 14 directory roles in the Microsoft-managed version, so Azure owners, custom role holders and anyone added later are covered. It also keeps exclusions granted in ATMO-MXDR-CA-MFA-ALLUSERS from reaching the admin portals, and it is the policy that later carries phishing-resistant strength for admins. Microsoft Admin Portals covers the Exchange admin center, the Azure portal (which also serves the Entra admin center), the Microsoft 365 admin portal and the Security and Compliance center. Windows Azure Service Management API is left out.

**Microsoft-managed policies.** Microsoft creates Block legacy authentication, Block device code flow, Multifactor authentication for admins accessing Microsoft Admin portals and Multifactor authentication for all users in eligible tenants, and switches them on no less than 30 days later. Once the ATMO-MXDR policies are on, the build sets these managed duplicates to Off so exclusions and evidence live in one place.

**Without report-only.** The 30-day sign-in review carries the weight that report-only used to. ATMO-MXDR-CA-MFA-ALLUSERS is the one policy that reaches every account, so the build confirms MFA registration coverage with the client before switching it on.

**Device code exceptions.** Where Teams Rooms or signage devices need device code flow, the exception is scoped by device group and network location, following Microsoft's guidance for Teams devices. Sessions that started with device code flow stay tracked through token refresh, so the block can end a session that began before it.

**Clients without Entra ID P1.** Security defaults stand in for the five policies. They block legacy authentication, require MFA for administrators and require every user to register for MFA. They do not block device code flow or restrict sign-ins by location, so IA.3-DEVICECODE and IA.4-LOCATION are recorded as documented exceptions until the client licenses P1. IA.1 also reads lower, since security defaults prompt users for MFA only when Microsoft judges it necessary.

## Diagnostic logging through Azure Policy

Azure resource telemetry comes from one Atmosera-owned initiative, ATMO-MXDR-DIAG-TOSENT, that sends audit-focused resource logs to the client Sentinel workspace. It uses a Microsoft category group wherever one matches the approved list and names categories explicitly everywhere else.

### How the initiative is built

- Assigned at the client's top management group, or at each subscription where none exists, with the DeployIfNotExists effect.
- One user-assigned managed identity per client, ATMO-MXDR-DIAG-MI, holds Monitoring Contributor and Log Analytics Contributor.
- A remediation task runs for each policy in the initiative, because policies otherwise apply only to resources created after assignment.
- Each policy and the diagnostic setting it writes share one name, ATMO-MXDR-TYPE-TOSENT, where TYPE is the short code in the table below.
- Before assignment, the build lists existing diagnostic settings that already send the same categories to the workspace and removes them, so nothing is ingested twice.
- Category group membership is confirmed once in the build lab with az monitor diagnostic-settings categories list before each initiative version is published.
- Sentinel data connectors are not used for these resource types.

### Approved categories by resource type

| Name | Resource type | Logs collected | Method |
| --- | --- | --- | --- |
| ATMO-MXDR-KV-TOSENT | Key Vault | AuditEvent | Built-in category group policy, group audit |
| ATMO-MXDR-AA-TOSENT | Automation Account | AuditEvent, JobLogs | Custom policy with explicit categories, since the audit group holds only AuditEvent |
| ATMO-MXDR-APP-TOSENT | App Service web apps | AppServiceAuditLogs, AppServiceIPSecAuditLogs, AppServiceFileAuditLogs, AppServiceAntivirusScanAuditLogs, AppServiceAuthenticationLogs | Built-in category group policy, group audit, if the lab check shows it returns these five. Custom policy otherwise. File audit and antivirus scan logs exist on Premium plans only |
| ATMO-MXDR-LOGIC-TOSENT | Logic Apps (Consumption) | WorkflowRuntime | Built-in category group policy, group allLogs, which holds only WorkflowRuntime |
| ATMO-MXDR-RSV-TOSENT | Recovery Services vault | CoreAzureBackup, AddonAzureBackupJobs, AzureSiteRecoveryJobs, AzureSiteRecoveryEvents, AzureBackupOperations | Custom policy with explicit categories and the resource-specific destination table |
| ATMO-MXDR-BASTION-TOSENT | Azure Bastion | BastionAuditLogs | Built-in category group policy, group audit |
| ATMO-MXDR-AI-TOSENT | Azure AI services | Audit | Built-in category group policy, group audit |
| ATMO-MXDR-MYSQL-TOSENT | MySQL Flexible Server | MySqlAuditLogs | Built-in category group policy, group audit. The build also sets audit\_log\_enabled to ON and limits audit\_log\_events to CONNECTION, DDL, DCL and ADMIN |
| ATMO-MXDR-ACT-TOSENT | Subscription Activity Log | Administrative, Security, Policy | Custom policy at subscription scope |

### Changes from the draft list

1. **JobLogs moved to Automation Accounts.** It records runbook job status and helps spot unexpected runbook runs. Logic Apps Consumption emits only WorkflowRuntime.
2. **AzureBackupOperations replaces AddonAzureBackupAlerts.** The old category records only classic Backup alerts, which Microsoft has on a deprecation path. The new one records operations run from the on-premises agent that the vault audit misses, such as stopping protection with data deletion and passphrase changes.
3. **Backup tables use resource-specific mode.** CoreAzureBackup and the AddonAzureBackup tables are resource-specific tables. Key Vault, Automation and Logic Apps Consumption write to AzureDiagnostics, their only option.
4. **Four sources added.** Bastion, AI services, MySQL Flexible Server and the Activity Log are now on the approved list. MySQL event types leave out query-level DML so the volume stays at audit level.
5. **Logic Apps Standard needs its own line.** It runs on App Service, and its WorkflowRuntime log sits outside the App Service audit group.

Entra ID sign-in and audit logs, Defender XDR and Microsoft 365 are tenant services rather than Azure resources, so they stay on their Sentinel connectors. Firewall and web application firewall traffic logs carry far higher volume and sit under the defense in depth logging control.

## Defense in depth controls

Twenty-eight defense in depth controls (seven under identity since Oct 12, 2026, when privileged role eligibility and the advanced anti-phishing policy moved out of the foundational tier, and six under network since the same day, when workload subnet segmentation moved here and App Service minimum TLS 1.2 took its foundational slot, and later that day encryption in transit on published web apps moved to foundational and container-level anonymous blob access joined, and five under detection and response since Oct 16, 2026, when Defender for Identity sensors and domain controller telemetry took the slots of analytics rules and threat intelligence) carry the E, P and N grading and form the What comes next roadmap. Each one waits on something only the client can approve, schedule or license.

| Pillar | Defense in depth control | Why it waits | Measures |
| --- | --- | --- | --- |
| Identity and access | Phishing-resistant authentication required for all users | Changes sign-in methods for every user and needs guided registration waves | IA.2 |
| Identity and access | Identity Protection sign-in and user risk policies enforced, with leaked credential response | Needs Entra ID P2 | IA.11 |
| Identity and access | Access conditioned on device compliance and ownership | Needs Intune compliance across the fleet and a pilot group | IA.12 |
| Identity and access | Application consent governed by administrative approval | Needs a consent review workflow the client staffs | IA.13 |
| Identity and access | Cloud management plane limited to administrative roles | Needs a role review so only administrators reach Azure management | IA.14 |
| Identity and access | Privileged roles held through eligibility rather than standing assignment | Needs Entra ID P2 for Privileged Identity Management and an activation habit for every administrator | IA.6 |
| Identity and access | Advanced anti-phishing policy with impersonation and mailbox intelligence protection | Needs the Defender for Office 365 Standard preset or a custom policy, and tuning of the protected user and domain lists | IA.9 |
| Endpoint and workload | Platform integrity enforced through Secure Boot and vTPM | Needs Gen2 images and a redeployment or in-place upgrade during maintenance | EW.7 |
| Endpoint and workload | Attack surface reduction rules enforced in block mode | Needs an audit period per rule to find business impact | EW.11 |
| Endpoint and workload | Credential protection enforced and legacy credential exposure removed | Needs device and application compatibility testing | EW.12 |
| Endpoint and workload | Application allow-listing on corporate-owned devices | Needs an application inventory and a learning period | EW.13 |
| Endpoint and workload | Remote Desktop hardened with TLS and file transfer blocked | Needs a review of how administrators and vendors move files | EW.14 |
| Network and boundary | Network security groups applied across the estate | A network security group or a firewall route on every workload subnet, with platform subnets such as GatewaySubnet and AzureFirewallSubnet excepted. Needs a segmentation design and change windows for subnets that carry production traffic | NB.1 |
| Network and boundary | Perimeter rule sets reviewed with findings tracked | Needs the client's network owners in a recurring review | NB.9 |
| Network and boundary | Platform services isolated behind private endpoints | Needs dependency testing and a private DNS design | DP.1 |
| Network and boundary | Blob containers closed to anonymous access at the container level | Containers that serve public content, such as static assets, need a move to a CDN or signed URLs, and their owners confirm each one first. It keeps a container closed even if the account-level setting is later relaxed | DP.1-CONTAINERS |
| Network and boundary | Directory traffic signed and channel-bound | LDAP signing and channel binding can break older applications, so an audit period comes first | NB.10 |
| Network and boundary | NTLM restricted and NTLMv2 enforced fleet-wide | Needs NTLM auditing to find dependent systems | NB.11 |
| Data protection | Collaboration sharing boundaries defined and governed | Needs business owners to agree external sharing rules | DP.9 |
| Data protection | Endpoint disk encryption enforced on managed devices | Needs recovery key escrow confirmed and device compatibility checked | DP.10 |
| Data protection | Key vault access governed by role-based access control | Needs access policies mapped to role assignments and application testing | DP.2 |
| Data protection | Encryption at host on virtual machines and scale sets | Needs feature registration and a deallocation inside a maintenance window | DP.4 |
| Data protection | Azure Backup enabled on all persistent virtual machines | Two steps. Confirming which machines persist and which are excluded by agreement has no cost, so it starts in Now when fewer than half of the machines carry a protected backup item. Extending Azure Backup adds recurring cost and waits for that agreement | DP.5b |
| Detection and response | Automated attack disruption active on identity threats | Needs Defender XDR prerequisites and agreement on automatic containment actions | DR.12 |
| Detection and response | Defender for Identity sensors healthy on domain controllers | Needs Defender for Identity licensing and a sensor on each domain controller from the client. Not in scope for cloud-only tenants | DR.11 |
| Detection and response | Domain controller telemetry collected continuously | Needs the same Defender for Identity licensing and sensors, which supply the domain controller events. Not in scope for cloud-only tenants | DR.4 |
| Detection and response | Vulnerability assessment running estate-wide | Endpoint assessment comes with onboarding. Server and container coverage follows the Defender for Cloud plans enabled at build | DR.5 |
| Detection and response | Diagnostic logging enabled on all platform resources | Extends logging past the approved audit set and adds ingestion cost | DR.13 |

### Where the two decks differed

| Item | In the decks | Placement here |
| --- | --- | --- |
| Platform integrity through Secure Boot and vTPM | Foundational in one, defense in depth in the other | Defense in depth, since it needs redeployment |
| Encryption at host | Foundational under endpoint in one deck, defense in depth under data protection in both | Defense in depth under data protection only |
| Public network access on storage | Foundational in one deck | Defense in depth as private endpoints |
| Directory traffic signed and channel-bound | Foundational in one, defense in depth in the other | Defense in depth, since it can break older applications |
| Vulnerability assessment | Both columns in one deck | Defense in depth only |
| Remote Desktop hardening | Listed twice in one deck | Listed once |
| Privileged role and Azure role assignments | One row in each deck | Merged into one row covering both |
| Internet-facing machines protected by network security groups | Foundational in one deck | Split into the management port and estate-wide network security group rows |
| Transport encryption on data platform services | Defense in depth in one deck | Folded into legacy and plaintext protocols, foundational |
| Sensitivity labeling | Out of scope in both decks | Slot given to Azure Backup, so data protection is graded out of 15 |
| AD attack path exposure, configuration baselines continuously assessed, self-service password reset, secure protocols on Windows servers | One deck each | Not carried, available as alternates |

## Measurement and review changes

Foundational rows are expected at E at every review, and anything less is reported as drift with a fix date. Five measures need work, and the current pillar slides carry five grading errors worth fixing before the next cycle.

### Measures

| Measure | Issue | Change |
| --- | --- | --- |
| DR.6 Diagnostic logging | Counts Defender for Cloud assessment entries, where one resource can appear several times, across types outside the approved list | DR.6 reports compliance of ATMO-MXDR-DIAG-TOSENT, counted per resource. Coverage beyond the approved set moves to DR.13 |
| NB.5 App Service minimum TLS 1.2 | Reads 0 percent in both reviews, 0 of 545 and 0 of 15, while new apps default to TLS 1.2 | Check the collector before presenting. Azure Resource Graph often returns site configuration values as empty, which would read as non-compliant |
| DP.1 Storage closed to public networks | Counts only accounts with public network access disabled | Also count accounts restricted to selected networks, with the default action set to Deny |
| Email protections | Safe Links and Safe Attachments carry IA.9 IDs but sit under data protection | Give the email controls one pillar and one ID family |
| New measures | 24 slide controls had no EBR measure | Drafted in Measure definitions as IA.10 to IA.14, EW.8 to EW.14, NB.7 to NB.11, DP.8 to DP.10 and DR.10 to DR.13 |
| DR.6 report row (Oct 12, 2026) | The foundational row Diagnostic logging enabled on platform resources duplicated the defense in depth DR.13 row | Removed from the report. DR.6-INITIATIVE grades the foundational telemetry row and DR.13 the defense in depth logging row. DR.6 stays in the pack as a backlog fallback |
| Conditional Access rows (Oct 12, 2026) | Device code and legacy sign-ins by accounts excluded from the block policy read as a failure, and no sign-ins read as in force | IA.1-ADMINPORTAL, IA.3 and IA.3-DEVICECODE are graded from the policy JSON (IA.8-POLICIES) with each successful sign-in matched to the policy result in its sign-in record (IA.8-SIGNINS). Excluded accounts are approved exceptions. With no policy inventory and no sign-ins of the kind, the row reads N/A |
| Conditional Access row replaced (Oct 12, 2026) | Conditional Access evaluated at sign-in counted the share of sign-ins any policy applied to, which says nothing about what the policies enforce | Replaced by Location-based sign-in access controls enforced through Conditional Access (IA.4-LOCATION), graded from the policy JSON like the other Conditional Access rows. IA.4 stays in the pack for reference |
| Encryption in transit tier (Oct 12, 2026) | Encryption in transit on published web apps sat in defense in depth | Moved to foundational under network, so network holds six foundational and six defense in depth rows |
| Container-level anonymous access (Oct 12, 2026) | The account-level setting was the only anonymous access reading, and a container left public becomes readable again if the account setting is relaxed | DP.1-CONTAINERS (collector 1.11.0) reads each container's own access level in every storage account through the Storage resource provider and grades the new defense in depth row. Containers readable today stay in the presenter notes and the SecOps worklist |
| Endpoint sensor scope (Oct 12, 2026) | The sensor row counted workstations and any device Defender discovered, including network devices | The row reads Azure virtual machines only. Collector 1.11.0 also drops network devices and firewalls (Palo Alto, Meraki, Fortinet, SonicWall and similar) from EW.1 and EW.1-DEVICES |
| Network virtual appliances (Oct 12, 2026) | Marketplace firewall images were graded on Trusted Launch, encryption at host, Azure Backup and agent-based recommendations they cannot take | Machines whose plan or image publisher is a firewall, router or SD-WAN vendor are listed in P0.6-APPLIANCES and left out of EW.7, EW.8, DP.4, DP.5b and those DFC.1 rows |
| Detection and response tiers (Oct 16, 2026) | Defender for Identity sensors and domain controller telemetry sat in foundational, though they need licensing and a sensor on each domain controller from the client and do not apply to cloud-only tenants. Analytics rules and threat intelligence sat in defense in depth, though the standard rule set and ingestion are switched on at build | DR.11 and DR.4 moved to defense in depth and go to Later on the roadmap with the licensing ask. DR.9 and DR.7 moved to foundational, renamed to what the build delivers, and a gap goes first in Now as Atmosera's fix. DR.9 became a presence check, an enabled rule in every Sentinel workspace, since the evidence cannot identify the standard rule set and disabled rules must not read as a foundational gap. Tuning against operating history and blocking on matched indicators are not graded. DR.12 still reads E only when DR.11 is at E, now within one tier |
| Legacy authentication (Oct 14, 2026) | Every failed legacy sign-in counted as blocked, so a password spray against a tenant with no block policy read as a perfect score | IA.3 is graded from the block policy like IA.3-DEVICECODE and renamed Legacy authentication blocked. Only error 53003 counts as a Conditional Access block. Without a policy inventory, no block and no success reads N/A, for device code too. Security defaults log their block as error 530035, which the collector does not yet count |

### Slide grading

| Finding | Detail | Fix |
| --- | --- | --- |
| Two E thresholds | One deck sets E at 95 percent and P at 50 to 94. The other sets E at 90 and P at 50 to 89 | E at 90 percent and P at 50 to 89 in every deck |
| Data protection shows 14 points but grades out of 15 | 12 of 14 is 85.7 percent, a B, shown as B-. 13 of 14 is 92.9 percent, an A-, shown as B | Grade on the points shown. With Azure Backup in the fifth slot, every pillar is out of 15 |
| Detection and response at 14 of 15 | 93.3 percent is an A on the stated scale. One deck shows A- and the other A | A in both |
| Endpoint and workload in the second deck | The pillar box shows B and the summary shows B-. 13 of 15 is 86.7 percent | B in both places |
| Identity and access in the second deck | 11.5 of 15 is 76.7 percent, shown as C+ | State the rounding rule. Unrounded it is a C |

## Measure definitions

Each of the 24 controls that had no measure now has a draft ID, a count and a data source. Counts follow the existing pattern of compliant items out of in-scope items over a stated window. A control with no countable population reads In force or Not in force, as IA.9 does today.

- New numbers start after the highest ID seen in the current reviews, at IA.10, EW.8, NB.7, DP.8 and DR.10, so they cannot collide with an existing ID. Confirm against the collector before release in case unseen numbers sit above those.
- Defender Vulnerability Management secure configuration data is not ingested into Sentinel. The collector reads it through Defender XDR advanced hunting or the Defender for Endpoint secure configuration export API.
- Windows are 30 days for device and sign-in activity and 90 days for reviews.

### Foundational measures

| ID | Control | Counts | Data source |
| --- | --- | --- | --- |
| IA.4-LOCATION | Location-based sign-in access controls enforced through Conditional Access | In force when an enabled Conditional Access policy with a country or named location condition blocks access or requires MFA for all users and all resources | Microsoft Graph Conditional Access policies (IA.8-POLICIES), evaluated offline by the report builder |
| IA.10 | Privileged role assignments governed and reviewed | Privileged Entra directory role assignments and Azure privileged administrator role assignments at subscription or management group scope that are PIM-eligible or carry a review in the last 90 days, of all such assignments | Microsoft Graph role assignments and role eligibility schedules, Azure Resource Graph authorizationresources, and the Atmosera review record |
| EW.8 | Tamper protection enforced so agents cannot be disabled | Onboarded devices with tamper protection on, of onboarded devices seen in the last 30 days | Defender Vulnerability Management secure configuration assessment for tamper protection |
| EW.9 | Host firewall enforced centrally through endpoint policy | Onboarded Windows devices with Defender Firewall on for the domain, private and public profiles, of onboarded Windows devices seen in the last 30 days. A device counts only when all three pass | Defender Vulnerability Management secure configuration assessments for the three firewall profiles |
| EW.10 | OS and Azure VM extension findings remediated on cadence | Machines with no missing security update or open extension finding older than the agreed cadence, of machines assessed | Azure Update Manager assessments in Azure Resource Graph patchassessmentresources, Defender for Cloud assessments in securityresources, and Defender Vulnerability Management for devices outside Azure |
| NB.7 | No management ports exposed directly to the internet | Virtual machines with no inbound rule allowing RDP or SSH from the internet, of virtual machines with a public IP address | Defender for Cloud assessment Management ports should be closed on your virtual machines, read from Azure Resource Graph securityresources |
| NB.8 | Egress and DNS monitored for tunneling and command traffic | Onboarded Windows devices with network protection in block mode, of onboarded Windows devices seen in the last 30 days. Reads E only when the Atmosera DNS tunneling and beaconing rules are enabled in Sentinel | Defender Vulnerability Management secure configuration assessment for network protection, and the Sentinel analytics rules API |
| DP.8 | Data loss prevention enforced across mail and endpoint | Licensed locations covered by at least one enabled policy in enforce mode, of licensed locations among Exchange, SharePoint, OneDrive, Teams and devices. Locations declined in the SOW are not in scope | Get-DlpCompliancePolicy in Security and Compliance PowerShell, reading Mode and the location properties |
| DR.9 | Analytics rules enabled in every Sentinel workspace | In force when every Sentinel workspace in scope has at least one enabled analytics rule, and Not in force when a workspace that was read has none. A partial read cannot confirm every workspace and stays ungathered. It does not identify which rules are Atmosera's. Enabled of total rules is reported as context and does not move the grade | Sentinel analytics rules through the ARM API, summarized per workspace (DR.9, DR.9-RULES) |
| DR.10 | Every alert triaged to a documented disposition | Incidents closed in the last 30 days with a classification and a closing comment, of all incidents closed in the last 30 days | Sentinel SecurityIncident table, Classification and ClassificationComment columns |

### Defense in depth measures

| ID | Control | Counts | Data source |
| --- | --- | --- | --- |
| IA.11 | Identity Protection sign-in and user risk policies enforced, with leaked credential response | In force when enabled Conditional Access policies for sign-in risk and user risk both target all users. Hybrid tenants also need password hash sync, which leaked credential detection depends on | Microsoft Graph Conditional Access policies, and Entra Connect sync settings |
| IA.12 | Access conditioned on device compliance and ownership | Successful interactive member sign-ins in the last 30 days from devices marked compliant or Entra hybrid joined, of all successful interactive member sign-ins | Sentinel SigninLogs, DeviceDetail isCompliant and trustType |
| IA.13 | Application consent governed by administrative approval | In force when user consent is off or limited to low-risk permissions from verified publishers, and the admin consent workflow is on | Microsoft Graph authorizationPolicy permissionGrantPoliciesAssigned and adminConsentRequestPolicy isEnabled |
| IA.14 | Cloud management plane limited to administrative roles | Successful sign-ins to Windows Azure Service Management API in the last 30 days by members of the approved administrator group, of all successful sign-ins to it | Sentinel SigninLogs, matched against the approved administrator group in Microsoft Graph |
| EW.11 | Attack surface reduction rules enforced in block mode | Onboarded Windows devices with every rule in the Atmosera standard set in block mode, of onboarded Windows devices seen in the last 30 days | Defender Vulnerability Management secure configuration assessments for each attack surface reduction rule |
| EW.12 | Credential protection enforced and legacy credential exposure removed | Onboarded Windows devices with LSA protection on and WDigest credential caching off, of onboarded Windows devices seen in the last 30 days | Defender Vulnerability Management secure configuration assessments for LSA protection and WDigest |
| EW.13 | Application allow-listing on corporate-owned devices | Corporate-owned Windows devices with an allow-listing policy in enforced mode, of corporate-owned Windows devices | Intune device ownership and App Control for Business policy status, or the ThreatLocker portal where the client runs ThreatLocker |
| EW.14 | Remote Desktop hardened with TLS and file transfer blocked | Windows servers with RDP on that require Network Level Authentication and TLS and block drive and clipboard redirection, of Windows servers with RDP on | Defender Vulnerability Management secure configuration assessments, or Azure machine configuration for Azure servers |
| NB.9 | Perimeter rule sets reviewed with findings tracked | Perimeter rule sets with a review in the last 90 days and every finding linked to a ticket, of perimeter rule sets in scope | Atmosera review record, with the Azure Firewall policy and internet-facing network security group inventory from Azure Resource Graph |
| NB.10 | Directory traffic signed and channel-bound | Domain controllers that require LDAP signing and LDAP channel binding, of domain controllers. Not in scope for cloud-only tenants | Defender Vulnerability Management secure configuration assessments on domain controllers, with Directory Service events 2889 and 3039 to find clients still binding without signing or channel binding |
| NB.11 | NTLM restricted and NTLMv2 enforced fleet-wide | Onboarded Windows devices with LAN Manager authentication level set to send NTLMv2 only and refuse LM and NTLM, of onboarded Windows devices seen in the last 30 days | Defender Vulnerability Management secure configuration assessment for LAN Manager authentication level, with NTLM sign-ins from IdentityLogonEvents to find dependent systems |
| DP.1-CONTAINERS | Blob containers closed to anonymous access at the container level | Blob containers whose own access level is private, of all blob containers, read in every storage account whatever the account-level setting | Azure Resource Graph for the storage accounts, then GET blobServices/default/containers on the Storage resource provider for each one |
| DP.9 | Collaboration sharing boundaries defined and governed | In force when the tenant sharing level, default link type and anonymous link expiration match the boundaries agreed with the client | Get-SPOTenant, reading SharingCapability, DefaultSharingLinkType and RequireAnonymousLinksExpireInDays |
| DP.10 | Endpoint disk encryption enforced on managed devices | Managed Windows and macOS devices reported as encrypted, of managed Windows and macOS devices | Intune managed device isEncrypted property in Microsoft Graph |
| DR.12 | Automated attack disruption active on identity threats | Onboarded devices in device groups set to Full or Semi automation, of onboarded devices. Reads E only when DR.11 is at E and the attack disruption exclusion list is documented | Device group remediation levels at System > Settings > Endpoints > Device groups in the Defender portal, with group membership from the MachineGroup column of DeviceInfo |
| DR.11 | Defender for Identity sensors healthy on domain controllers | Domain controllers with a healthy, up-to-date Defender for Identity sensor, of domain controllers in the directory. Not in scope for cloud-only tenants | Microsoft Graph security/identities/sensors, reading sensorType, healthStatus and deploymentStatus, compared with the domain controller list |
| DR.13 | Diagnostic logging enabled on all platform resources | Resources with every Defender for Cloud diagnostic and audit logging assessment healthy, of resources with at least one such assessment | Defender for Cloud assessments in Azure Resource Graph securityresources, counted per resource |

## Sources

- [Microsoft-managed Conditional Access policies](https://learn.microsoft.com/en-us/entra/identity/conditional-access/managed-policies)
- [Conditional Access authentication flows](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-authentication-flows)
- [Block authentication flows with Conditional Access](https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-block-authentication-flows)
- [Conditional Access target resources, including Microsoft Admin Portals](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-cloud-apps)
- [Built-in Azure Policy for diagnostic settings by category group](https://learn.microsoft.com/en-us/azure/azure-monitor/platform/diagnostic-settings-policy-built-in)
- [Azure Monitor built-in policy reference, including the Activity Log policy](https://learn.microsoft.com/en-us/azure/azure-monitor/policy-reference)
- [App Service built-in policy reference](https://learn.microsoft.com/en-us/azure/app-service/policy-reference)
- [App Service monitoring data reference](https://learn.microsoft.com/en-us/azure/app-service/monitor-app-service-reference)
- [App Service minimum TLS version and TLS 1.0 and 1.1 retirement](https://learn.microsoft.com/azure/app-service/tls-minimum-version)
- [Azure Backup diagnostics data model](https://learn.microsoft.com/en-us/azure/backup/backup-azure-reports-data-model)
- [Supported logs for Recovery Services vaults](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/supported-logs/microsoft-recoveryservices-vaults-logs)
- [Supported logs for Logic Apps workflows](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/supported-logs/microsoft-logic-workflows-logs)
- [Supported logs for Automation accounts](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/supported-logs/microsoft-automation-automationaccounts-logs)
- [Audit logs in Azure Database for MySQL flexible server](https://learn.microsoft.com/en-us/azure/mysql/flexible-server/concepts-audit-logs)
- [Azure Storage TLS 1.0 and 1.1 retirement, The Register](https://www.theregister.com/2026/02/03/microsoft_tls_deprecations/)

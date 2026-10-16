# Get-EbrSecurityEvidence.ps1

**READ-ONLY.** This script runs every query in the *EBR Security Evidence Collection Runbook*
(Oct 7, 2026) for one client and writes an evidence pack. Every figure in it traces back to a
query ID. You supply the client's tenant and subscription IDs; the script does the rest.

## Quick start

```bash
pwsh ./Get-EbrSecurityEvidence.ps1
```

The script prompts for the tenant (a GUID or a domain) and the subscription IDs, then works
through the run sequence: pre-flight, outcomes, control evidence, posture and backlog.

```bash
pwsh ./Get-EbrSecurityEvidence.ps1 -TenantId contoso.onmicrosoft.com -SubscriptionId a0c307ad-f1c3-4a7d-96c3-10a6eb7c9c62
```

```bash
pwsh ./Get-EbrSecurityEvidence.ps1 -TenantId <guid> -SubscriptionId <sub1>,<sub2> -WindowStart 2026-01-01 -WindowEnd 2026-07-31
```

```bash
pwsh ./Get-EbrSecurityEvidence.ps1 -TenantId <guid> -SubscriptionId <sub1> -DryRun
```

A dry run writes every expanded query to `queries/` without signing in, so you can paste
the queries by hand. Graph items are written as `queries/<ID>.graph.txt` with the endpoints
they read.

```bash
pwsh ./Get-EbrSecurityEvidence.ps1 -TenantId <guid> -SubscriptionId <sub1> -SkipGraph -PatchCadenceDays 45
```

`-SkipGraph` restores the pre-1.7 behaviour (Graph items UNAVAILABLE with their portal path).
`-PatchCadenceDays` is the agreed cadence for EW.10, default 30.

```bash
pwsh ./Get-EbrSecurityEvidence.ps1 -TenantId <guid> -SubscriptionId <sub1> -EdrVendorPattern 'crowdstrike|falcon' -PatchExclusionTagPattern ''
```

`-EdrVendorPattern` names the third-party endpoint detection products in the environment (CrowdStrike
Falcon is in the default), so an Azure virtual machine that runs one is reported as covered rather than
as not onboarded. `-PatchExclusionTagPattern ''` turns off the tag-based patch exclusion.

## What it decides for you

| Runbook parameter | How the script sets it | Override |
|---|---|---|
| Subscription IDs | You supply them | `-SubscriptionId` |
| Sentinel workspaces | Every workspace with the SecurityInsights solution in those subscriptions. One per subscription is normal. See [Multiple workspaces](#multiple-workspaces) | `-WorkspaceResourceId` (one or more) |
| Managed resource group pattern | `aznativesol0`, the same on every client subscription. Every resource that belongs to it is excluded from evaluation. ARG queries test the resource id. Records that describe another resource test that resource's id instead: backup items (`DP.5`, `DP.5-STALE`, `DP.5b`), policy states (`DR.6-INITIATIVE`), Defender for Cloud alerts (`BKL.2`), Defender devices in Advanced Hunting (`AzureResourceId`) and recommendation snapshots (`POS.8`). Subscription-level results (`P0.3`, `POS.1`, `POS.3`, `POS.5`, `POS.7`) and the workspace inventory (`P0.2`) carry no exclusion | `-ManagedRgPattern` (`''` removes the exclusion) |
| Alert scope | Only incidents whose comments or closing comment reference an Atmosera ticket (Zendesk ticket URL, or `per ZD ticket NNNN`). Informational severity is excluded. Applies to OUT.1 to OUT.7, and detections (OUT.5, OUT.6) are limited to the alerts linked to those incidents | `-TicketPattern` (an RE2 regular expression, no double quotes) |
| Incident reporting window | From the first full month of `SecurityIncident` data in any workspace (P0.1) to the end of the last full month. This gives the maximum reach | `-WindowStart` / `-WindowEnd` (yyyy-MM-dd) |
| Posture read date | The run date | n/a |
| Service start date | Not available from any API. The worksheet marks it MANUAL | n/a |
| Device scope | Every Defender device query (EW.1, EW.1-DEVICES, EW.1-VMS, EW.3, EW.4, EW.5, EW.12, EW.14, EW.15, EW.16, NB.8, NB.10, NB.11, DR.5, DR.12, BKL.1) reads Azure virtual machines only, `isnotempty(AzureResourceId)`. Workstations, laptops and other endpoints that are not Azure resources are never counted (1.14.0) | n/a |
| Third-party endpoint detection | `crowdstrike|falcon|sentinelone|carbon ?black|cortex ?xdr|cybereason|tanium|trellix|cylance`, matched against virtual machine extension publishers and types (`EW.1-EDR`) and against the Sentinel tables and vendors carrying the product's telemetry (`EW.1-EDR-HOSTS`). An Azure virtual machine that is not onboarded to Defender for Endpoint but carries a matching product is covered, not a gap (`EW.1-GAPS`). Recorded as `EdrVendorPattern` in `00-parameters.json` | `-EdrVendorPattern` (RE2, no double quotes) |
| Patching waived or client owned | A regular expression against the lowercased JSON of each machine's tags. The default matches a tag whose key or value names patching together with waived or client owned (`Patching=Waived`, `PatchPolicy=Client Owned`, `Maintenance=Patching waived`). Matching machines leave `EW.6` and `EW.10` and are listed in `EW.10-EXCLUDED`. Recorded as `PatchExclusionTagPattern` in `00-parameters.json` | `-PatchExclusionTagPattern` (RE2, `''` turns the exclusion off) |

**Scope safety.** Every subscription must be homed in the client tenant (`homeTenantId` in
`az account list`), or the script stops before running anything. Resource Graph calls always
list those subscriptions explicitly and never use tenant scope.

**Direct access first.** The script prefers a direct sign-in to the client tenant over
Lighthouse, because Lighthouse gives an incomplete IA.7. Through Lighthouse, Resource Graph
returns the managing tenant's delegations instead of the client's own Owner and User Access
Administrator assignments. Every other query reads the same either way. The script works it
out like this:

1. Checks whether a client-tenant token can see every subscription. If yes, it uses direct access.
2. If not, it offers to run `az login --tenant <the tenant you typed>`, your usual step, and checks again.
3. If you decline, or it still can't see every subscription, it falls back to Lighthouse. It
   then marks IA.7 PARTIAL and says so in the notes.

The notes and `00-parameters.json` record which path was used.

## How each engine is reached

The Azure CLI issues every token, including the Microsoft Graph one. Graph is read with GET
requests only, on the instruction of Oct 11, 2026, for the measures that have no other source.
ATMOSERA_SCRIPT_REQUIREMENTS.md 1.4 still forbids Graph; that standard has not been updated.

| Engine | Endpoint | Token |
|---|---|---|
| Resource Graph | `management.azure.com/.../Microsoft.ResourceGraph/resources` (paged) | `az account get-access-token`, the subscription's access tenant |
| Log Analytics | `api.loganalytics.io/v1/workspaces/{id}/query`. A combined query adds the other workspaces in the `workspaces` body field | same |
| Advanced Hunting | `api.security.microsoft.com/api/advancedqueries/run` | resource `api.securitycenter.microsoft.com`, client tenant |
| Sentinel rules (DR.9) | `{workspace}/providers/Microsoft.SecurityInsights/alertRules` | ARM |
| Microsoft Graph (IA.1-FEDERATION, IA.5, IA.6, IA.8, IA.11, IA.13, POS.6, DP.8, DP.10, DR.11, EW.13) | `graph.microsoft.com/v1.0`, GET only, `@odata.nextLink` paging | resource `https://graph.microsoft.com/`, client tenant, same reauth prompt as Defender |
| Exchange Online and Purview (IA.9, DP.7-ZAP, DP.6) | `ExchangeOnlineManagement` module, browser sign-in | module |

**What the Graph token can read.** The Azure CLI application carries a fixed set of delegated
Graph permissions. On the first live run (Oct 11, 2026, a GDAP account with directory
roles in the client tenant) the token read the organization, user registration details (IA.5),
role assignments (IA.6, standing only), Conditional Access policies (IA.8, IA.11) and the
authorization policy (IA.13). It could not read PIM schedule instances, the admin consent
request policy, on-premises synchronization, Secure Score, Intune or Defender for Identity
sensors, and SharePoint settings answered 401 rather than 403. A 401 or 403 marks that one
measure **UNAVAILABLE** with the permission it needs, the `az login --scope` command that
requests it, and the portal path. A measure that still produced rows with a gap (IA.6 without
eligibility, IA.11 without password hash sync, IA.13 without the workflow) says so in its detail
and is listed as "partly" in the notes. The notes end with one combined command for every
missing permission, for example:

```bash
az login --tenant <client-tenant-id> --scope https://graph.microsoft.com/Policy.Read.All https://graph.microsoft.com/SecurityEvents.Read.All
```

`--scope` takes several scopes as separate arguments, so do not quote the list. Requesting a
scope needs consent in the client tenant, which a GDAP or guest account may not be able to
grant. Across the three tenants run on Oct 11, 2026 the same eight scopes were missing every
time (RoleManagement.Read.Directory, OnPremDirectorySynchronization.Read.All, Policy.Read.All
for the consent workflow, DeviceManagementConfiguration.Read.All, SharePointTenantSettings.Read.All,
DeviceManagementManagedDevices.Read.All, SecurityIdentitiesSensors.Read.All,
SecurityEvents.Read.All), so this is a property of the Azure CLI application's consent, not of
one client. The substitutes (IA.6-SUB, IA.8-SUB, POS.6-SUB, the BitLocker row of EW.3 for
DP.10, DR.4 for DR.11) still run either way.

**What the Defender endpoint can reach.** The `advancedqueries/run` endpoint that Azure CLI
tokens work with is the Defender for Endpoint one. It serves the device and vulnerability
tables (`Device*`, `DeviceTvm*`), but never `IdentityInfo`, `IdentityLogonEvents` or
`EmailPostDeliveryEvents`, whatever the client licenses. The Defender XDR hunting endpoint
does serve those, but it rejects Azure CLI tokens ("Missing application scopes").

So IA.6-SUB, DP.7 and DR.4 go straight to the Sentinel workspaces. If Sentinel doesn't collect
those tables, run the saved `queries/<ID>.kql` in Defender portal > Advanced hunting by hand.

If an Advanced Hunting query fails, or the Defender token can't be issued, the script first
checks which Defender tables the Sentinel workspaces actually hold (last 30 days):

- A query whose tables are all present runs against the workspaces, and its result counts as
  a reading. The manifest `Source` says `Sentinel workspace (AH fallback)`.
- A query that needs a table the workspaces lack is marked **UNAVAILABLE**. It is reported as
  "no figure, not a zero" and never fills a worksheet value. The `DeviceTvm*` tables only exist
  in Advanced Hunting, so their queries are always UNAVAILABLE without the Defender API.

**Fresh-MFA prompt.** Some client tenants enforce a Conditional Access sign-in frequency on
the Defender API. They reject a saved session with `AADSTS50078` ("multi-factor
authentication has expired"). When that happens the script offers a browser sign-in to the
client tenant and retries. To do it yourself before a run:

```bash
az login --tenant <client-tenant-id> --scope https://api.securitycenter.microsoft.com/.default
```

Lighthouse calls (Resource Graph, Log Analytics) are not affected: their tokens come from the
Atmosera tenant.

## Multiple workspaces

Many clients have one Sentinel workspace per subscription. The script uses all of them.

| Query type | How it runs | Why |
|---|---|---|
| Workspace-level: incidents, alerts, Usage, threat intelligence, SecureScores, SecurityRecommendation, and the Advanced Hunting fallback | Once **combined** across all workspaces in a single Log Analytics call. That result feeds the worksheet. Also once **per workspace**, written to `<ID>-BY-WORKSPACE` with `Workspace` and `SubscriptionId` columns | Medians, P90s and distinct counts are only correct when computed over the combined data. Adding up per-workspace answers gets them wrong |
| Tenant-wide: SigninLogs (IA.1–IA.4b, IA.2-METHOD, IA.8-SUB) and AuditLogs (OUT.8) | Once, against whichever workspace holds the most of that table (from P0.1) | Every copy holds the same sign-ins, so combining copies would double-count |
| DR.9 Sentinel rules | Per workspace. The summary is split by scope (all workspaces, then each workspace) | Rules live in each workspace |

Details:

- **Incident keys.** OUT.1, OUT.2, OUT.3, OUT.4 and OUT.7 summarize `by TenantId, IncidentNumber` (`TenantId` is the workspace ID), so incident 12 in two workspaces stays two incidents. With one workspace the result is identical to the runbook query. **Update the runbook text to match.**
- **Score trend key.** POS.7 also keys each score by subscription, falling back to workspace (`ScoreKey`). `_ResourceId` alone doesn't separate subscriptions, so the combined trend used to show one subscription's score. **Update the runbook text to match.**
- **P0.1-XDRDUP** does two checks:
  - If Sentinel holds **no** Defender XDR incidents, the notes warn that the OUT figures cover only Defender for Cloud, Sentinel analytics and Identity Protection.
  - If the same XDR incident was synced into more than one workspace, the notes warn that the combined OUT.1 and OUT.3 counts include it more than once.
- **Missing tables.** A workspace that lacks a table counts as having no data for it, not as an error, and is left out of the combined query.
- **PARTIAL.** A combined result is PARTIAL when a workspace failed for any other reason. That workspace is left out, and worksheet values built on the result carry a PARTIAL note.
- **`-SkipWorkspaceBreakdown`** runs only the combined queries, which is faster. P0.1 still runs per workspace, because choosing the tenant-wide workspace and the window depends on it.

### Graph items

| ID | Endpoint | Permission | Substitute when Graph cannot read it |
|---|---|---|---|
| IA.1-FEDERATION Federated domains | `domains`, then `domains/{id}/federationConfiguration` for each federated domain. A subdomain that inherits its root's federation answers 404 and is recorded as inherited | Domain.Read.All | Without it the report treats the tenant as federated when IA.1 shows federated sign-ins |
| IA.5 Registered methods | `reports/authenticationMethods/userRegistrationDetails` | AuditLog.Read.All | Portal path in the manifest |
| IA.6 Privileged roles | `roleManagement/directory/roleAssignmentScheduleInstances` and `roleEligibilityScheduleInstances`, falling back to `roleAssignments` without PIM | RoleManagement.Read.Directory | **IA.6-SUB**: current privileged role holders from `IdentityInfo` |
| IA.8 Conditional Access inventory | `identity/conditionalAccess/policies` | Policy.Read.All | **IA.8-SUB**: every CA policy seen in 30 days of sign-ins |
| IA.11 Risk policies in force | the cached IA.8 list, plus `directory/onPremisesSynchronization` | Policy.Read.All (and OnPremDirectorySynchronization.Read.All for password hash sync) | none |
| IA.13 Consent governance | `policies/authorizationPolicy`, `policies/adminConsentRequestPolicy` | Policy.Read.All | none |
| POS.6 Tenant Secure Score | `security/secureScores?$top=90`, `security/secureScoreControlProfiles`. Also writes POS.6-TREND and POS.6-CATEGORIES | SecurityEvents.Read.All | **POS.6-SUB**: device secure score and exposure score from the Defender API |
| DP.8 SharePoint sharing | `admin/sharepoint/settings` | SharePointTenantSettings.Read.All | Portal path in the manifest |
| DP.10 Disk encryption | `deviceManagement/managedDevices` | DeviceManagementManagedDevices.Read.All | The BitLocker row of EW.3, used by the HTML report |
| DR.11 Defender for Identity sensors | `security/identities/sensors` | SecurityIdentitiesSensors.Read.All | DR.4 domain controller events |
| EW.13 App Control policies | `beta/deviceManagement/configurationPolicies` filtered to the App Control template family (beta only; v1.0 has no settings catalog) | DeviceManagementConfiguration.Read.All | Intune admin center, or the ThreatLocker portal |

Results carry counts and flags into the HTML report. Names, UPNs, domains and policy titles stay
in the pack (`results/<ID>.csv`).

### Runbook variants it also runs

- Control measures added on Oct 11, 2026: `IA.1-ADMINPORTAL`, `IA.3-DEVICECODE`, `IA.14`, `EW.10` (patch cadence), `EW.12`, `EW.14`, `EW.15`, `EW.16`, `NB.8`, `NB.10`, `NB.11` (per-device secure configuration checks), `DP.7-ZAP`, `DR.10`, `DR.12`, `DR.13` and `DR.6-INITIATIVE`. The runbook has one block per query.
- `OUT.2-ANALYST`: OUT.2 without incidents closed by automation rules.
- Every OUT query carries the ticket scope clause (`{{TICKET}}`) and the informational exclusion. `00-parameters.json` records `TicketPattern` and `AlertScope`.
- `OUT.2-RECENT` and `OUT.2-RECENT-ANALYST`: the same two queries over the trailing three full months of the window (`RecentStart` in `00-parameters.json`). They are context for the analyst. The HTML report presents one fixed cohort from `OUT.2` and never falls back to them.
- `IA.2-METHOD`: IA.2 split by method.
- `DFC.1-DETAIL`, `EW.7-DETAIL`, `DP.4-DETAIL`: the itemized lists the runbook asks for.
- `DR.9-RULES`: every analytics rule.
- `IA.9-RULES`, `IA.9-ATP`, `IA.9-SAFELINKS`, `IA.9-SAFEATTACH`: the remaining IA.9 output, plus Safe Links and Safe Attachments policies for DP-F3.
- `OUT.1-OPEN`, `DR.10-GAPS`, `EW.1-DEVICES`, `DP.5-STALE` (collector 1.8.0): the row-level lists behind OUT.1 open alerts, DR.10 undocumented closures, EW.1 devices not onboarded or with an inactive sensor, and DP.5 stale backup items. They feed the internal SecOps worklist and are never embedded in the client report. `EW.1-VMS`, `EW.1-EDR`, `EW.1-EDR-HOSTS`, `EW.1-GAPS` and `EW.10-EXCLUDED` (collector 1.14.0) are the same kind of list: the report embeds counts only.
- Collector 1.10.0:
  - `IA.8-POLICIES` keeps the Conditional Access policies exactly as Graph returned them (with the excluded user, group and role IDs), and `IA.8-DEFAULTS` records whether security defaults are on. `IA.8-SIGNINS` lists every successful device code and legacy protocol sign-in in 30 days per account, with the policyId=result pairs from the sign-in record. The report builder and the SecOps worklist match the two, so a sign-in by an account the block policy excludes is an approved exception rather than a failure. `IA.3` no longer counts the Unknown client app as legacy authentication.
  - `P0.6-APPLIANCES` lists machines on a marketplace firewall, router or SD-WAN image (plan or image publisher matching `$script:EbrAppliancePattern`, recorded as `AppliancePattern` in `00-parameters.json`). They are left out of `EW.7`, `EW.7-DETAIL`, `EW.8`, `DP.4`, `DP.4-DETAIL`, `DP.5b` and the agent, disk, platform integrity and backup rows of `DFC.1` and `DFC.1-DETAIL`. Network recommendations such as management ports still apply to them.
  - `EW.1-DEVICES` covers Azure virtual machines only, in any onboarding status other than Onboarded.
  - `DP.5-STALE` carries a `Finding` per item (Superseded, Source deleted, Protection stopped, Not protected, Backup stale). Superseded means a current healthy item protects the same machine, either the same resource in another vault or a machine of the same name whose old resource is gone. `DP.5b` counts a machine as protected when any of its items is Protected.
  - The ticket pattern keeps the Zendesk subdomain in the extracted reference.
- Collector 1.11.0:
  - `DP.1-CONTAINERS` reads every blob container's own anonymous access level. Resource Graph does not index containers, so the collector lists the storage accounts through Resource Graph and then calls `GET <account>/blobServices/default/containers` on the Storage resource provider for each one (Reader is enough). One row per account with the account setting, the containers, the containers set to Blob or Container access, and how many are readable anonymously today. An account it cannot list is recorded with the error and the result reads PARTIAL. Expect roughly one second per storage account.
  - `EW.1` and `EW.1-DEVICES` drop network devices and firewalls that Defender discovers on the network (Palo Alto, Meraki, Fortinet, SonicWall and similar, `$script:EbrNetworkDevicePattern`), because they cannot run a sensor. The DR-F1 sensor ratio in the worksheet reads Azure virtual machines only.
- Collector 1.12.0 (October 13, 2026, method in `docs/Federated MFA Evaluation.md`):
  - `IA.1` classifies each successful sign-in by the strongest MFA evidence it carries: an MFA step at Entra, MFA asserted by the federated identity provider, a phishing-resistant credential, or MFA carried in the session (the requirement field, the claim in the token, or a policy whose only grant is Require multifactor authentication, enforced or report-only). Sign-ins without evidence are grouped by path, and a reused session that no policy checked reads "Session reuse, MFA not evaluated", not as a sign-in without MFA. Windows logon and device registration are left out before the per-user count, because a federated Windows logon (WS-Trust) can never carry MFA. Still one row per `UserType`, with partner technicians (GDAP) and outbound passthrough as their own rows. The earlier columns keep their names (`UsersSignedIn`, `UsersChallenged`, `UsersAlwaysMfa`, `UsersExternalMfa`, `UsersEntraMfa`, `PctChallenged`, `PctAlwaysMfa`) next to the member view of the method (`MfaAtLeastOnce`, `MfaEveryAppSignIn`, `CoveredEveryAppSignIn`, `FederatedMfaAtLeastOnce`, `FederatedWithoutMfa`, `NoMfaOnlyUnevaluated`). The tenant-specific phishing-resistant policy name is gone, because that authentication strength rejects federated MFA.
  - `IA.1-ADMINPORTAL` uses the same classification and adds `FederatedMfaAtLeastOnce`, `FederatedWithoutMfa`, `NoMfaOnlyUnevaluated` and `NotEvaluatedSignIns`.
  - `IA.1-FEDERATION` (Graph, Domain.Read.All) records each federated domain with its issuer, sign-in URIs, protocol, `federatedIdpMfaBehavior` and the identity provider named from the URIs (Okta, AD FS, Ping or Other). EMPTY means no federated domain.
  - In a federated tenant the HTML report grades IA.1 and IA.1-ADMINPORTAL without the members whose only sign-ins were unevaluated sessions, and explains the method in a presenter note. Packs collected before 1.12.0 grade as before, with a presenter note asking for recollection when members show federated MFA.
- Collector 1.13.0 (October 14, 2026, Q5 in `docs/Federated MFA Evaluation.md`):
  - `IA.1` and `IA.1-ADMINPORTAL` start with a session pre-pass (`let MfaSessions`) over 90 days of successful sign-ins in every app, bounded in practice by workspace retention. It records the earliest direct MFA in each `SessionId` (Entra step, federated provider claim, phishing-resistant credential, requirement field or claim in the token, never policy results). A sign-in without direct evidence whose session had direct MFA at or before it reads "MFA earlier in the same session" and counts as MFA. The rule sits after the federated, device logon and report-only interrupted rules and before session reuse.
  - "Session reuse, MFA not evaluated" also takes a sign-in that presents a PRT or refresh token without the "Previously satisfied" step.
  - `IA.1` adds `MfaSessionLinkedOnly`: users whose only MFA evidence is the session inference. The HTML report names it in the presenter notes only.
  - On Shook, Q5 moved 232 of the 1,884 "No MFA evidence, no session reuse" sign-ins to the session rule and 87 to session reuse, so the member figures from 1.12.0 shift.
- Collector 1.14.0 (October 14, 2026):
  - Every Defender device query reads Azure virtual machines only: `EW.1`, `EW.1-DEVICES`, `EW.3`, `EW.4`, `EW.5`, the per-device checks (`EW.12`, `EW.14`, `EW.15`, `EW.16`, `NB.8`, `NB.10`, `NB.11`), `DR.5`, `DR.12` and `BKL.1` filter on `isnotempty(AzureResourceId)`. The `Scope` column stays, always `Azure VM`. The report leaves the Other device rows of older packs out as well, so network protection reads as Azure virtual machines in block mode, not the workstation fleet. `EW.1` adds `Unsupported` and `InsufficientInfo`.
  - `EW.1-VMS` lists every Azure virtual machine Defender has seen in the last 7 days, in any status. `EW.1-EDR` (Resource Graph) lists every Azure virtual machine with the Defender for Endpoint extension, any extension whose publisher or type matches `-EdrVendorPattern`, the Defender for Cloud EDR assessment status, the power state and the appliance flag. `EW.1-EDR-HOSTS` (Log Analytics) lists the hosts reporting to a third-party product through Sentinel in the last 7 days (the `CrowdStrike*` tables and `CommonSecurityLog` by vendor).
  - `EW.1-GAPS` is derived from those results without a query: one row per Azure virtual machine that is not onboarded with an active sensor, with the reason (covered by a third-party product, network virtual appliance, operating system not supported, deallocated, discovered only, not discovered by Defender, sensor not active, not onboarded with no endpoint detection found), the product, the evidence and whether the machine stays in the onboarding denominator. The report counts a machine covered by CrowdStrike Falcon or another product as protected and writes the reasons under both the onboarding figure and the sensor figure, so the two reconcile on the page. The SecOps worklist names each machine.
  - `EW.6` and `EW.10` leave out machines whose tags record patching as waived or client owned (`-PatchExclusionTagPattern`), and `EW.10-EXCLUDED` names them. The report note states the count.
  - `IA.1` and `IA.1-ADMINPORTAL` read In force or Not in force from the Conditional Access policy inventory when the report builder has it (a new MFA at sign-in flow in `report/Get-EbrCaEvaluation.ps1`), with the sign-in ratio in the note.
  - Every output keeps to the copy rules: no semicolons, arrows or emoji in the worksheet, notes, manifest guidance, worklist, report or deck, and the greater-than sign only in portal navigation steps.
- Collector 1.13.1 (October 14, 2026):
  - Exchange Online and Purview connect with `-CommandName`, so each connect builds its temporary module from only the cmdlets the collectors call (`$script:EbrExoCommands`, `$script:EbrIppsCommands`) rather than every cmdlet the role allows. Exchange also skips format data, and Purview no longer downloads and prints its announcement banner. Parameters an older ExchangeOnlineManagement does not know are left out. Results are unchanged.
  - On Windows the run turns QuickEdit off in its console and restores it at the end. With QuickEdit on, a click in the window (coming back from a sign-in, or selecting output to copy) starts a text selection that pauses the script at its next line of output until Esc or Enter. That was the whole slowdown of an October 14 Shook run: step 5 took 87 minutes (20 seconds on a Mac) and P0.1 and OUT.1 took 16 and 13 minutes (14 and 8 seconds). It uses `Add-Type` for `GetConsoleMode` and `SetConsoleMode` in kernel32 and does nothing when there is no console or QuickEdit is already off.
  - Step 5 prints and logs how long each stage took (Exchange connect with sign-in, Exchange reads, Purview connect with sign-in, sign-out), and any request that takes 30 seconds or more is written to `run.log` with its duration. A slow run with no slow requests was held up at the console or the machine, not the network.
- Managed resource group exclusion on every query that names a resource (collector 1.9.0). Before 1.9.0 only the ARG property queries carried it, so Defender devices, backup items, policy states, Defender for Cloud alerts and recommendation snapshots from `aznativesol0` were still counted.

## Output

Completed collections also create an offline executive HTML report. See
[HTML report usage and metric rules](New-EbrSecurityReport.README.md) for report depth,
existing-pack generation and dated delivery context. Keep `New-EbrSecurityReport.ps1` and
the `report` folder beside the collector. The default depth is Balanced. Use
`-ReportDepth Brief` or `-ReportDepth Detailed` to change it, or `-SkipHtmlReport` to opt out.

The script writes `EBR-Evidence_<client>_<yyyyMMdd-HHmmss>/`:

| File | Contents |
|---|---|
| `00-manifest.csv` | One row per result set: ID, phase, engine, source, status (OK, EMPTY, PARTIAL, UNAVAILABLE, FAILED, SKIPPED, MANUAL), row count, read time (UTC), detail (which workspaces were combined, missing or failed) and the runbook guidance |
| `00-parameters.json` | Tenant, subscriptions, workspaces and how each is reached, which workspace supplied the tenant-wide tables, window and its basis, managed RG pattern, warnings |
| `01-worksheet.csv` | The runbook's slide map (48 rows). Values are filled in wherever they can be derived, each with a read date and a note. `MANUAL` means a portal reading; `REVIEW` means the data is collected but an analyst has to do the calculation. The MFA rows quote **members**, with guests and other user types in the note. A user counts as challenged when any successful sign-in satisfied MFA through the requirement field, a step detail claim (in the token or from an external identity provider) or `MfaDetail`, so federated tenants are not under-counted. The note states how many members relied on an external provider claim. When automation rules closed at least half the incidents, the close-time rows quote the **analyst-handled** figures (OUT.2-ANALYST, per the runbook), labelled as such, with the all-incident figure in the note. Fewer than 20 incidents behind a median or P90 adds a small-sample caveat. The anti-malware row quotes the weakest check and lists every check, with scope and OS, in the note. Privileged roles read "N role assignments across M accounts", because PIM state is unknown without Graph |
| `02-notes.txt` | Ticket notes ready to paste: scope, collection summary, key figures, attention items |
| `04-secops-worklist.md`, `04-secops-worklist.csv` | Internal SecOps worklist written by `New-EbrSecOpsWorklist.ps1`: open alerts with incident number and Zendesk ticket, closures without a documented disposition, devices not onboarded or with an inactive sensor, virtual machines without backup, stale backup items and the row-level platform gaps. Names resources, so it stays with the SecOps team. `-SkipSecOpsWorklist` opts out. See [SecOps worklist](New-EbrSecOpsWorklist.README.md) |
| `03-security-report.pptx` | PowerPoint edition of the report, same figures, slides following the report depth, talking-point speaker notes only. Needs Node.js and pptxgenjs, skipped with a warning without them |
| `03-security-report.html` | Self-contained executive security report: headline tiles, four tier posture block, measured outcomes by pillar, E, P, N control matrix, sequenced roadmap, score context and screen-only presenter notes. Client-facing copy says alerts, never incidents |
| `queries/<ID>.kql` | The exact query text that ran, with the dates filled in |
| `results/<ID>.csv`, `results/<ID>.json` | The rows (client-level, combined). Nested values are JSON-encoded in the CSV, and decimals are written to 15 significant digits in invariant culture (`130.36`, never `130.35999999999999` or `130,36`) |
| `results/<ID>-BY-WORKSPACE.csv` | The same query run once per workspace, with `Workspace`, `WorkspaceId` and `SubscriptionId` columns first |
| `run.log` | Timestamped log. Never contains tokens |

The script grades nothing automatically. E, P and N grades need analyst judgment, for
example the NB.2 association verdicts.

## Prerequisites and permissions

- PowerShell 7.x recommended. Windows PowerShell 5.1 also works.
- Azure CLI 2.50 or later (`brew install azure-cli` or `winget install Microsoft.AzureCLI`).
- The `ExchangeOnlineManagement` module, installed automatically for the current user unless
  you pass `-SkipExchange`.

| Data | Role needed |
|---|---|
| Resource Graph, Defender for Cloud | Reader (or Security Reader) on the subscriptions |
| Log Analytics, Sentinel rules | Microsoft Sentinel Reader or Log Analytics Reader on the workspace |
| Advanced Hunting, Defender scores | Security Reader (Defender XDR) in the client tenant |
| Microsoft Graph | Global Reader in the client tenant, plus the delegated permissions in the Graph items table consented to the Azure CLI application. Missing ones are named in the notes |
| Exchange Online, Purview DLP | Global Reader, or Security Reader plus View-Only Organization Management |

## Sign-ins

1. **Azure CLI.** The script reuses your current session. If it can't see the subscriptions,
   it opens a browser sign-in (`az login --tenant <client>`); device code is never used.
   Lighthouse-only access: run `az login` against the Atmosera tenant first.
2. **Exchange Online and Purview.** One or two browser windows, early in the run so the rest
   can run unattended. When your account is from another tenant (GDAP or guest), the script
   adds `-DelegatedOrganization` automatically.

## Exit codes

`0`: everything collected. `2`: finished, but one or more result sets are FAILED, PARTIAL
or UNAVAILABLE (see the manifest), or HTML report generation needs attention. `1`: fatal error, such as bad input, a failed sign-in or a
subscription from another tenant.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `Subscription ... is homed in tenant X, not the client tenant` | The wrong subscription for this client. This is the script working as intended |
| `Still cannot see subscription(s)` | Run `az login` against the tenant that holds your Lighthouse or GDAP access, then rerun |
| `AADSTS530004` / "AcceptCompliantDevice setting isn't configured" | The client requires a compliant device for the Defender API, but doesn't trust device compliance from Atmosera. Signing in again can't fix this. A client admin enables Entra admin center > External Identities > Cross-tenant access settings > Atmosera (or Default) > Inbound access > Trust settings > **Trust compliant devices**, or excludes your access from that policy. Until then, paste the saved `queries/<ID>.kql` files into Defender portal > Advanced hunting |
| `AADSTS53000` / `53001` / `530002` / `530003` | Your device isn't compliant or managed by the client's standard. Sign in from an Intune-compliant device, using a browser that passes device state |
| `AADSTS53003` | A client Conditional Access policy blocked you. The client's Entra sign-in log names the policy |
| IA.7 is PARTIAL | The run went through Lighthouse. Run `az login --tenant <client domain>` (or accept the prompt) and rerun |
| `AADSTS50078` / "multi-factor authentication has expired" | The client's Conditional Access wants a fresh MFA for the Defender API. Accept the script's sign-in prompt, or run the `az login --scope` command above, then rerun |
| Many results are UNAVAILABLE | Advanced Hunting couldn't be reached and the Sentinel workspaces don't hold those tables. These rows have no data, not a zero. Fix the Defender sign-in, or check that you have a Defender XDR role in the client tenant |
| A Graph result is UNAVAILABLE and names a permission (`GRAPH-403`) | The Azure CLI token lacks that delegated Graph permission in the client tenant. Run the `az login --scope` command from the notes (it asks for consent), then rerun. If consent is refused, the portal path in the manifest is the reading |
| `Graph probe failed` or `No Graph token` | Graph itself could not be reached with the client tenant token, for the same Conditional Access reasons as the Defender API. Every Graph item is UNAVAILABLE with its portal path; the substitutes still ran. `-SkipGraph` silences the attempt |
| DP.6 says `Get-DlpCompliancePolicy` was not loaded | Purview PowerShell only loads the cmdlets your role allows. Your GDAP or guest account needs a role with DLP read access (for example Compliance Administrator or Compliance Data Administrator). Otherwise read it in the Purview portal |
| The notes say incident data is cut off by retention | The earliest record is the workspace's retention limit, not the service start. Earlier months need a search job or the CyberSOC reports |
| Pack is named after the tenant ID | No name was found anywhere, and Exchange was skipped or failed. Normally the name comes from the Exchange organization. Otherwise enter the tenant as a domain, or pass `-ClientName` |
| DP.6: "Unexpected character encountered while parsing value: <" | Purview was given a tenant GUID. The script now passes it the organization's `.onmicrosoft.com` domain, read from Exchange first. If Exchange failed, enter the tenant as its domain |
| A workspace "holds no data" | It's a Sentinel-enabled workspace with nothing in it (a demo, say). It adds nothing. Leave it out by listing the real workspaces with `-WorkspaceResourceId` |
| EW.3, EW.4, DR.5, BKL.1 FAILED with "failed to resolve table" | `DeviceTvm*` tables exist only in Advanced Hunting, so the fallback can't reach them. Fix the Defender API access, or grade from Secure Score (P0.4 warning) |
| POS.7 and POS.8 EMPTY | Continuous export is off (P0.1 warning). Use a dated screenshot for trends |
| A result is PARTIAL | One workspace errored and was left out of the combined figure. The manifest detail names it and gives the error |
| P0.1-XDRDUP warning in the notes | Defender XDR incidents are synced into several workspaces. Count each XDR incident once using the BY-WORKSPACE files before quoting OUT.1 or OUT.3 |
| The run stalls until you press Enter, often after a sign-in | QuickEdit in the classic Windows console: a click in the window starts a text selection and pauses the script. 1.13.1 turns QuickEdit off for the run. With an older version, press Esc or Enter, or untick QuickEdit Mode in the console window's Properties. A stall with no slow request in `run.log` points at the console or the machine (sleep), not the network |
| A run with many workspaces is slow | Each workspace-level query runs N+1 times. Use `-SkipWorkspaceBreakdown` for combined figures only |
| IA.9 or DP.6 FAILED with a sign-in error | Check your Exchange or Purview role. Use `-SkipExchange` to run without them |

## Tests

```bash
pwsh -NoProfile -c "Invoke-Pester ./tests/Get-EbrSecurityEvidence.Tests.ps1 -Output Detailed"
```

The Pester suite covers:
- the catalog and query expansion
- the read-only guard
- response conversion
- window maths
- tenant checks
- worksheet derivation
- the Graph GET helper, the Graph initialiser and every Graph collector against mocked responses,
  including the 403 to UNAVAILABLE mapping
- an end-to-end run of the whole script against three mocked workspaces (one returns errors,
  one lacks a table, Defender returns 403, and Graph answers role assignments but not policies)

Nothing in it signs in or calls Azure.

## Read-only guarantee

`Assert-EbrReadOnlyRequest` runs before every REST call. It allows GET anywhere, and POST
only to the three query endpoints (Resource Graph, Log Analytics, Advanced Hunting).
Everything else throws before a request is sent. The Exchange and Purview cmdlets used are
all `Get-*`.

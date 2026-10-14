# MXDR Controls Baseline Review

Oct 11, 2026. A review of docs/MXDR Security Controls Baseline and Hardening.md against collector version 1.6.1, the runbook, the report model and the two evidence packs collected on Oct 11, 2026 (Shook, Hardy and Bacon, and Vision Precision Holdings).

## Status, Oct 11, 2026

Implemented the same day in collector 1.7.0: a read-only Microsoft Graph engine with tokens from the Azure CLI (finding 1 is now a per-client permission question rather than a blocker, and the standards file is unchanged), the report threshold at 90 (finding 3), every non-duplicate measure from the feasibility tables under the IDs the collector already used (finding 2 resolved by numbering tamper protection EW.15 and host firewall EW.16), and the worksheet and HTML report wired to the new results. Design and plan: docs/plans/2026-10-11-graph-engine-and-new-controls-design.md. Findings 4 to 11 stand.

## Verdict

The control plan is sound. The placement rules are crisp, the Conditional Access design is coherent and checks out against Microsoft's published admin portal list, and the diagnostic logging initiative is well reasoned with build tooling already in the scripts folder. The weak part is the measurement layer. The document was written without checking the collector, so four of its new measure IDs collide with IDs already in use, two of its five "measures that need work" are already fixed, and seven of its new measures name Microsoft Graph as their only source while the Atmosera script standard forbids Graph.

On feasibility, 28 of the 50 controls already have a working measure in the collector today. Thirteen more are a new query on an engine that exists. Four need a composite rule or a client parameter. Seven are blocked on the Graph decision. One needs a new SharePoint connection. Two stay manual.

## Findings on the plan, ranked

### 1. Seven measures depend on Microsoft Graph, which the script standard forbids

ATMOSERA_SCRIPT_REQUIREMENTS.md section 1.4 states that the Graph API is not permitted under any circumstances. That is why the collector has no Graph engine and why IA.5, IA.6, IA.8, DP.8 and POS.6 read MANUAL in every pack. The new document names Graph as the sole source for:

| Measure | Graph dependency | Non-Graph substitute available today |
| --- | --- | --- |
| IA.10 Privileged roles | Directory role assignments and PIM eligibility schedules | IdentityInfo in Sentinel gives role holders (IA.6-SUB) but not eligibility. IA.7 covers the Azure half, incomplete through Lighthouse |
| IA.11 Identity Protection policies | Conditional Access policy objects | IA.8-SUB sees a risk policy only when it fires in a sign-in |
| IA.13 Application consent | authorizationPolicy and adminConsentRequestPolicy | None |
| IA.14 Management plane to admins | Approved administrator group membership | None. Azure CLI's az ad commands call Graph too |
| DP.10 Disk encryption | Intune managedDevice isEncrypted | Defender Vulnerability Management check scid-2090, Encrypt all BitLocker-supported drives, already in EW.3 output. Windows only |
| DR.11 Domain controller sensors | security/identities/sensors | DR.4 reads IdentityLogonEvents per domain controller. Needs the Defender for Identity connector in Sentinel because the XDR hunting API rejects Azure CLI tokens |
| EW.13 Allow-listing | Intune App Control policy status | ThreatLocker API only, where the client runs it. Get-ThreatLockerGroupDevices.ps1 in the scripts folder shows that access exists |

This is a decision, not a bug. Either the standard gains a read-only delegated Graph exception with a fixed scope list, or the document adopts the substitutes above and accepts that IA.13 and the consent half of identity governance stay manual. The PIM, consent and Intune checks have no other source.

### 2. Four new measure IDs collide with IDs the collector already uses

The document says new numbers start after the highest ID seen and cannot collide, and asks for a check against the collector before release. The check fails.

| Document assigns | Collector 1.6.1 already uses it for |
| --- | --- |
| EW.8 Tamper protection | Guest Configuration extension coverage |
| EW.9 Host firewall | Guest Configuration assignment compliance |
| NB.7 Management ports | DNS and egress telemetry present |
| DP.8 Data loss prevention | SharePoint and OneDrive sharing |

Six more are duplicates of existing measures under a new number: the document's DP.8 is today's DP.6, its NB.7 is NB.2, its DP.9 is DP.8, its DR.11 overlaps DR.4, its EW.11 overlaps EW.4 and EW.5, and its IA.12 is a second cut of IA.4b. Fix: reuse the existing IDs where the measure is the same, and start the genuinely new ones at EW.10, NB.8, DP.9 and DR.10.

### 3. The E threshold is 90 in two places and 95 in two others

The document and the runbook (line 314) set E at 90 percent. The report design record (line 42) and report-model.js line 31 set it at 95. The document's "two E thresholds" finding applies to the code as well as the decks. One-line change in the model once the number is settled, plus the design record.

### 4. One measure ID serves several controls at different tiers

The report model grades one mark per measure ID. The document maps:

- DP.1 to three controls across two tiers (legacy protocols, anonymous access, private endpoints).
- DP.2 to purge protection (foundational) and RBAC (defense in depth).
- EW.1 to two foundational rows in two pillars.
- The IA.9 family to controls in two pillars, which the document itself flags but leaves in its tables.

Each needs a sub-ID the way IA.9-SAFELINKS works, for example DP.1-TRANSFER, DP.1-ANON, DP.2-PURGE, DP.2-RBAC. The private endpoint control should cite NB.3, which already exists, rather than DP.1.

### 5. Scoring of a foundational control that is out of scope is undefined

DR.11 does not apply to cloud-only tenants, DP.8 locations can be declined in the SOW, and IA.3-DEVICECODE is an exception without P1. The document still says every pillar is out of 15. The report model today omits a control with zero applicable resources, which silently shrinks the denominator. Pick one rule and write it down: either the pillar is graded out of fewer points, or a documented exception scores E.

### 6. Two measures need a cross-measure rule the report model does not have

NB.8 reads E only when the Sentinel tunneling rules are enabled, and DR.12 reads E only when DR.11 is at E and the exclusion list is documented. The model has control() for ratios and inForce() for booleans, nothing that combines two results. Small addition, but it has to be designed once.

### 7. The pre-enforcement check reads a table nothing collects

The 30-day sign-in review names service accounts on SMTP AUTH, POP and IMAP, and accounts that only sign in non-interactively. Those live in AADNonInteractiveUserSignInLogs. Neither the collector nor the runbook reads that table. Also, 30 days misses quarterly batch jobs. Use 90 days where SigninLogs retention allows (P0.1 reports the reach) and state 30 as the floor.

### 8. Eight of the new endpoint measures inherit the Defender API fragility

EW.8, EW.9, EW.11, EW.12, EW.14, NB.8, NB.10 and NB.11 all read DeviceTvmSecureConfigurationAssessment. In the Shook pack the Defender API token failed with AADSTS530004 (the client's Conditional Access requires a compliant device for external accounts), so every one of these would read UNAVAILABLE there, as EW.1 and EW.3 did. The build should either exclude the Atmosera analyst identity from that policy, or enable the Defender for Endpoint connector so the table lands in Sentinel and the fallback path works.

### 9. Two of the five "measures that need work" are already done

- NB.5 no longer reads zero. Version 1.6.1 reads appserviceresources with the PascalCase fix and the Oct 11 packs show 545 of 545 and 15 of 15.
- DP.1 already emits SelectedNetworks (default action Deny). Only the worksheet caption still quotes PublicNetworkOff alone.

### 10. Placement tensions worth a sentence each

- Host firewall on all profiles with existing rules in place. A server whose firewall was off has no rules to keep, so turning it on blocks inbound by default. By the document's own rule this needs dependency testing.
- SMBv1 off. Removing the feature needs a restart. Disabling the server protocol through configuration may not. State which mechanism the build uses.
- Patch cadence as foundational while patches need maintenance windows. Say explicitly that the process is the control and the outcome is tracked.
- Tenant-wide tamper protection can conflict with third-party tools that manage Defender settings. Add a coexistence check to the build.

### 11. Smaller gaps

- Logic Apps Standard is promised its own line in the logging table and never gets one.
- P earns half points is in the runbook but not in this document.
- ZAP is measured by DP.7 as removals, not as the setting. The setting is one Exchange cmdlet and would be a better foundational reading.

## Feasibility of the 50 controls

Ratings. Done means a working measure exists in 1.6.1. Query means a new catalog entry on an existing engine plus one line in the report model, hours each. Composite means existing engines but a fixed list, a client parameter or a cross-measure rule, a day or two each. Blocked means the named source is Graph or has no API. Manual means a portal or review reading.

### Foundational

| Pillar | Control | Doc measure | In collector today | Rating | Notes |
| --- | --- | --- | --- | --- | --- |
| Identity | MFA for all users | IA.1, IA.1-ADMINPORTAL | IA.1 | Done, Query | Admin portal filter on the four app IDs. Microsoft's list matches the document's |
| Identity | Conditional Access enforced | IA.4 | IA.4 | Done | Sign-in coverage. Policy state itself is Graph, so IA.8 stays manual |
| Identity | Legacy and device code blocked | IA.3, IA.3-DEVICECODE | IA.3 | Done, Query | AuthenticationProtocol column in SigninLogs |
| Identity | Privileged roles governed | IA.10 | IA.6 manual, IA.6-SUB, IA.7 | Blocked | PIM eligibility is Graph. Review record is a manual input |
| Identity | Anti-phishing | IA.9 | IA.9 | Done | Exchange Online |
| Endpoint | EDR deployed | EW.1 | EW.1 | Done | Advanced Hunting, see finding 8 |
| Endpoint | Anti-malware active | EW.3 | EW.3 | Done | |
| Endpoint | Tamper protection | EW.8 | scid-2003 in EW.3 | Query | ID collision |
| Endpoint | Host firewall | EW.9 | scid-2070 to 2073 in EW.3 | Query | Per-device all-profiles rule needs its own query. ID collision |
| Endpoint | Patch cadence | EW.10 | EW.6, DFC.1 | Composite | Cadence parameter per client, non-Azure leg from DVM |
| Network | Management ports | NB.7 | NB.2 | Done | ID collision. NB.2 already handles association |
| Network | Legacy protocols | DP.1, NB.6 | DP.1, NB.6, scid-53 and 54 in EW.3 | Done, Query | SMBv1 is a filter on EW.3 |
| Network | Anonymous access | DP.1 | AnonymousBlobOff | Done, Query | Endpoint share half has no named measure. scid-30 is the nearest check |
| Network | NSGs across the estate | NB.1 | NB.1 | Done | |
| Network | Egress and DNS monitored | NB.8 | scid-96 in EW.3, DR.9 rules engine | Composite | Fixed rule-name list, cross-measure rule. Existing NB.7 is dropped silently |
| Data | Platform encryption | DP.3 | DP.3 | Done | |
| Data | Key Vault purge protection | DP.2 | DP.2 | Done | Needs a sub-ID |
| Data | Safe Links and Attachments | IA.9-SAFELINKS, -SAFEATTACH | Both | Done | |
| Data | Malicious mail removed | DP.7 | DP.7 | Done, Query | Sentinel fallback only. The ZAP setting is one Exchange cmdlet |
| Data | Data loss prevention | DP.8 | DP.6 | Done | Failed on Shook for lack of a Purview role. ID collision |
| Detection | Telemetry collected | DR.6 | DR.6 (assessment count) | Query | Policy compliance via ARG policyresources. Reads nothing until the initiative is deployed |
| Detection | Workload protection | DR.2 | DR.2 | Done | |
| Detection | Sensor reporting | EW.1 | EW.1 | Done | Needs a sub-ID |
| Detection | Triage disposition | DR.10 | SecurityIncident table | Query | Apply the same Zendesk ticket scope as the alert figures |
| Detection | DC telemetry | DR.11 | DR.4 | Blocked | Graph sensors. DR.4 is the substitute |

### Defense in depth

| Pillar | Control | Doc measure | In collector today | Rating | Notes |
| --- | --- | --- | --- | --- | --- |
| Identity | Phishing-resistant | IA.2 | IA.2 | Done | |
| Identity | Identity Protection policies | IA.11 | IA.8 manual, IA.8-SUB | Blocked | Graph policy objects |
| Identity | Device compliance | IA.12 | IA.4b | Query | DeviceDetail columns, same table |
| Identity | Application consent | IA.13 | IA.8 manual | Blocked | Graph only, no substitute |
| Identity | Management plane to admins | IA.14 | None | Composite, Blocked | Sign-ins to app 797f4846 is a query. Group membership is Graph |
| Endpoint | Secure Boot and vTPM | EW.7 | EW.7 | Done | |
| Endpoint | ASR block mode | EW.11 | EW.4, EW.5 | Done | ID duplicate |
| Endpoint | Credential protection | EW.12 | scid-25, 102, 57 in EW.3 | Query | |
| Endpoint | Allow-listing | EW.13 | None | Blocked | Intune is Graph. ThreatLocker leg is a new engine |
| Endpoint | RDP hardening | EW.14 | scid-24, 45 in EW.3 | Composite | Drive and clipboard redirection checks absent from the 275-row Vision EW.3 output |
| Network | TLS on published services | NB.4, NB.5 | Both | Done | NB.5 already fixed |
| Network | Perimeter review | NB.9 | None | Manual | Inventory via ARG is a query. Review record is manual |
| Network | Private endpoints | DP.1 | NB.3 | Done | Cite NB.3 |
| Network | LDAP signing and binding | NB.10 | scid-103 to 106 in EW.3 | Query | Events 2889 and 3039 need the Directory Service log in Sentinel, not collected |
| Network | NTLM restricted | NB.11 | scid-72, 109 in EW.3 | Query | IdentityLogonEvents leg is XDR-only |
| Data | Sharing boundaries | DP.9 | DP.8 manual | New engine | Get-SPOTenant. SharePoint module is on the approved list. Needs SharePoint admin |
| Data | Disk encryption | DP.10 | scid-2090 in EW.3 | Query, Blocked | DVM covers Windows without Graph. macOS needs a check |
| Data | Key Vault RBAC | DP.2 | RbacAuth column | Done | Needs a sub-ID |
| Data | Encryption at host | DP.4 | DP.4 | Done | |
| Data | Azure Backup | DP.5b | DP.5b | Done | |
| Detection | Attack disruption | DR.12 | None | Manual, Query | No documented API for device group automation levels. Membership from DeviceInfo is a query |
| Detection | Detection tuning | DR.9 | DR.9 | Done | |
| Detection | Threat intelligence | DR.7 | DR.7 | Done | |
| Detection | Vulnerability assessment | DR.5 | DR.5 | Done | |
| Detection | Logging on all resources | DR.13 | DR.6 | Query | Re-key today's DR.6 per resource |

## Suggested order of work

1. Decide the Graph question. Everything in the Blocked rows waits on it.
2. Renumber the measures in the document against the catalog, add the sub-IDs, and settle the E threshold at 90 in report-model.js and the design record.
3. Add the Query rows. They are catalog entries plus a control() line each, and the DVM ones are filters on a query that already runs.
4. Add the composite rule to the report model and wire NB.8 and DR.12 to it.
5. Add the SharePoint connection next to the Exchange and Purview step for DP.9.
6. Write the not-in-scope scoring rule and the non-interactive sign-in review into the document.

## Gap analysis record

- Inversion. Three failure modes checked: measures that collide (found, finding 2), measures with no reachable source (found, findings 1 and 8), grading that differs between artifacts (found, finding 3). None is mitigated by the document as written.
- Second-order. Switching Conditional Access on without report-only is mitigated by the sign-in review, but the review cannot see non-interactive sign-ins today (finding 7). Acceptable once the table is added.
- MECE. Measurement is covered. Build delivery mechanics (which policy objects, which Intune profiles) are outside this review.
- Map versus territory. The Graph token path through Azure CLI was not tested against a tenant. The absence of a device group automation API was not verified against current Microsoft documentation. The Lighthouse path was not exercised in the Oct 11 packs.
- Adversarial. Weakest point is the Defender API token (finding 8). A client policy change silently blanks eight measures.
- Simplicity. The DVM substitutes for DP.10 and DR.11 are simpler than a Graph engine and are recommended regardless of the Graph decision.
- Reversibility. Every recommendation here is reversible except purge protection, which the document already gates on client approval.
- Confidence. HIGH on the code-verified findings (collisions, thresholds, Graph ban, NB.5 fixed, which DVM checks exist). MEDIUM on the feasibility ratings for the Blocked rows, which depend on the Graph decision and on two unverified API facts above.

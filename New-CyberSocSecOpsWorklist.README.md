# EBR SecOps worklist

`New-CyberSocSecOpsWorklist.ps1` turns a finished evidence pack into the list of items the SecOps team
resolves at the platform level under the managed security service. It is the internal counterpart
of the client report: the report shows counts and never names a resource, the worklist names every
incident, ticket, device and resource so someone can act on it. Keep it inside Atmosera.

## Generate from an existing evidence pack

```powershell
./New-CyberSocSecOpsWorklist.ps1 -EvidencePath ./CyberSOC-Evidence_Client_20261012-120000
```

Writes `04-secops-worklist.md` and `04-secops-worklist.csv` into the pack. `-OutputPath <folder>`
writes them elsewhere. The collector runs it after every collection unless `-SkipSecOpsWorklist`
is passed. Offline only. Nothing in the pack is changed.

## Categories

| Category | Source | What an item means |
|---|---|---|
| Open alerts | `OUT.1-OPEN` | A ticketed, non-informational alert created in the window and still open at collection. Incident number, severity, age, owner and the Zendesk ticket link (`https://atmosera.zendesk.com/agent/tickets/<number>`, set with `-ZendeskTicketUrl`) |
| Closed alerts without a documented disposition | `DR.10-GAPS` | Closed in the last 30 days with no classification, Undetermined, or no closing comment |
| Azure virtual machines not onboarded to endpoint detection | `EW.1-DEVICES`, `EW.1-GAPS` | An Azure VM seen in the last 7 days in any onboarding status other than Onboarded that carries no other endpoint detection product. Endpoints that are not native to Azure, and network virtual appliances, are left out and counted in the status line. With a 1.14.0 pack, machines covered by a third-party product, and machines that cannot take a sensor, move to the reason list below and each remaining item carries its reason |
| Azure virtual machines with an inactive sensor | `EW.1-DEVICES`, `EW.1-GAPS` | An onboarded Azure VM whose sensor state is not Active, with the reason when the pack has one (deallocated at collection, for example) |
| Azure virtual machines not reporting to Defender for Endpoint, by reason | `EW.1-GAPS` | Every Azure VM that is not onboarded with an active sensor, with the reason the collector established and its evidence: covered by a third-party product (CrowdStrike Falcon, or another product named by `-EdrVendorPattern`), a network virtual appliance, an operating system the sensor does not support, deallocated at collection, discovered only, never discovered by Defender, sensor not active, or not onboarded with no endpoint detection found. A machine covered by a third-party product counts as protected in the client report, so confirm the product is licensed and reporting |
| Machines left out of the patch measures by tag | `EW.10-EXCLUDED` | A virtual machine or Arc machine whose tags record patching as waived or client owned (`-PatchExclusionTagPattern`). It is left out of the patch cadence and pending patch figures. Confirm each tag is still intended |
| Device code and legacy sign-ins to review | `IA.8-SIGNINS`, `IA.8-POLICIES` | A successful device code or legacy protocol sign-in in the last 30 days, classified against the Conditional Access block policy: excluded (an exclusion to confirm with the client), not evaluated (usually before the policy existed) or not governed (no enabled block policy applies) |
| Legacy sign-ins that failed without a Conditional Access block | `IA.3` | One line per legacy protocol whose attempts in the last 30 days failed without a Conditional Access block (error 53003), with the blocked and successful counts. Most are a wrong password or a locked account. A large number points to password spraying against legacy endpoints. Packs without the `BlockedByCa` column say so instead of listing items |
| Virtual machines without Azure Backup | `DP.5b` | No Protected item in any vault. Machines sharing a resource group with a pooled AVD host pool (`DP.5c`) carry a note, since they may be excluded by agreement |
| Backup items stale or not protected | `DP.5-STALE` | Last backup older than 48 hours, or protection state not Protected. Items superseded by a current backup of the same machine (moved, rebuilt or protected in another vault) and deleted resources with protection stopped are left out and counted in the status line. For packs before collector 1.10.0 the finding is inferred from the VM inventory in `EW.7-DETAIL` and `DP.5b` |
| Virtual machines without Trusted Launch | `EW.7-DETAIL` | Security type is neither TrustedLaunch nor ConfidentialVM |
| Virtual machines without encryption at host | `DP.4-DETAIL` | Virtual machines and scale sets without the setting |
| Workload subnets without segmentation | `NB.1` | Workload subnets with no network security group and no route table |
| High severity Defender for Cloud recommendations | `DFC.1-DETAIL` | One line per unhealthy high severity recommendation, with every affected resource and resource group |
| Blob containers set to anonymous access | `DP.1-CONTAINERS` | A storage account holding containers whose own access level is Blob or Container, with the container names, how many are readable anonymously today and the account setting. Accounts whose containers could not be listed are shown with the error |
| Network virtual appliances excluded from VM measures | `P0.6-APPLIANCES` | A machine on a marketplace firewall, router or SD-WAN image that the collector leaves out of the VM measures. Confirm each really is an appliance |

Rows that name a resource in the managed resource group (`ManagedRgPattern` in `00-parameters.json`, default `aznativesol0`) are dropped before any category is built. Collector 1.9.0 already excludes them at query time. The check here covers packs collected earlier and reads the resource group, resource id, Azure resource id, source resource id and vault columns only, so an incident title is never matched.

Each category reports one of four statuses: a count of items, none found, not collected with the
manifest status, or needs recollection with the collector version that added the source (1.8 for
`OUT.1-OPEN`, `DR.10-GAPS`, `EW.1-DEVICES` and `DP.5-STALE`, 1.10.0 for `IA.8-SIGNINS` and
`P0.6-APPLIANCES`, 1.11.0 for `DP.1-CONTAINERS`, 1.14.0 for `EW.1-GAPS` and `EW.10-EXCLUDED`) when the pack predates it.

The Conditional Access classification is shared with the report builder through
`report/Get-EbrCaEvaluation.ps1`, so the worklist names exactly the accounts the report counts.

The CSV has one row per item: Category, ControlId, Resource, Detail, Reference, Source.

## Validation

```powershell
Invoke-Pester -Path tests/New-CyberSocSecOpsWorklist.Tests.ps1
```

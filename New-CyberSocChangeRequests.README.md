# Hardening change requests

`New-CyberSocChangeRequests.ps1` turns a finished evidence pack into the change requests for the security hardening
items that can be applied without affecting operations, laid out on the change request template. Every change
request also gets a client email, drafted and ready to send: an approval, confirmation or maintenance window request
for the changes that need the client first, and a notice of planned change for the others. The files name client
resources, so they stay internal until they are sent.

`Get-CyberSocEvidence.ps1` runs it at the end of every collection, after the SecOps worklist, unless
`-SkipChangeRequests` is given. It passes on `-DrClient`, `-SentinelWorkspace`, `-ManagementGroup`, `-ClientContact`,
`-SenderName` and `-PurgeProtectionApproved`, and records them under `ChangeRequests` in `00-parameters.json`.

## Generate from an existing evidence pack

```powershell
./New-CyberSocChangeRequests.ps1 -EvidencePath ./CyberSOC-Evidence_Contoso_2026-09_20261003-090000
```

Writes `05-change-requests` into the pack. Offline only. Nothing in the pack is changed.

| Parameter | Effect |
|---|---|
| `-OutputPath <folder>` | Writes the files elsewhere |
| `-DrClient` | DR Impact reads N/A - No DR impact instead of Not a DR Client, and the encryption at host changes add the DR Playbook step that Azure Site Recovery needs (CR-15 only when it holds a Flexible scale set, since Site Recovery does not replicate Uniform instances) |
| `-SentinelWorkspace <name>` | The workspace the diagnostic logging initiative sends to. Defaults to the pack's workspace when it holds one, otherwise the change names the client Sentinel workspace without its name |
| `-ManagementGroup <name>` | Assigns the diagnostic logging initiative once at this management group. Without it CR-01 assigns it at each subscription, since an assignment has one scope |
| `-ClientContact <name>` | The name the client emails open with. Without it they open with Hello |
| `-SenderName <name>` | The name under the sign-off of the client emails |
| `-PurgeProtectionApproved` | The client approved purge protection at build kickoff. CR-06 gets a notice of planned change that refers to that approval instead of an approval request, and the index notes the approval |
| `-ChangeDate <date>` | The day the changes with a notice of planned change are planned for. The notices ask the client to raise any concern a week before it. Defaults to two weeks after the build date, and must be at least eight days after it |

Run it again after a recollection, or on its own to write the files again with another contact, sender or planned
date, or on the day the emails are sent so their dates start from that day. The collector does not take
`-ChangeDate`, so a collection run always plans the notices two weeks after the build. To plan an agreed date, run
the generator again on the pack with it, for example
`./New-CyberSocChangeRequests.ps1 -EvidencePath <pack> -ClientContact 'Dana' -SenderName 'Scott' -ChangeDate 2026-11-16`. It replaces the change requests it wrote before, removes the ones the pack no
longer supports, and leaves every other file in the folder alone.

## The changes

Each change is written only when the pack shows resources still to fix. The numbers stay the same from run to run.

| CR | Change | Evidence | Client email |
|---|---|---|---|
| 01 | Diagnostic logging initiative ATMO-MXDR-DIAG-TOSENT assigned on every subscription. When it has no policy state anywhere (DR.6-INITIATIVE is EMPTY) it is assigned once at the management group named with `-ManagementGroup`, or at each subscription. When some subscriptions already have it, it is assigned at each subscription without a state (DR.6-COVERAGE). The covered resource types are counted from P0.5 | DR.6-INITIATIVE, DR.6-COVERAGE, P0.5 | Notice of planned change, with the resource types each subscription holds, and that the resource logs add Log Analytics ingestion to the Sentinel workspace (the Activity log is ingested at no charge) |
| 02 | Secure transfer required on storage accounts | DP.1-DETAIL | Notice of planned change, saying that a request over HTTP or an SMB connection without encryption is rejected once it is on |
| 03 | Minimum TLS 1.2 on storage accounts. Azure Storage has refused TLS 1.0 and 1.1 since February 3, 2026, so this aligns the configuration | DP.1-DETAIL | Notice of planned change, with no visible effect expected |
| 04 | Minimum inbound TLS 1.2 on App Service and Function apps. App Service refuses TLS 1.0 and 1.1 from May 31, 2027 | NB.5-DETAIL | Notice of planned change, saying that a client limited to TLS 1.0 or 1.1 can no longer connect |
| 05 | Minimum TLS 1.2 on Azure SQL logical servers. Azure SQL retired TLS 1.0 and 1.1 on August 31, 2025 | NB.6-DETAIL | Notice of planned change, with no visible effect expected, and that a minimum once set cannot return to the unset default |
| 06 | Purge protection on key vaults, with the soft delete retention period of each vault. Purge protection cannot be disabled once enabled, so the client approves it in writing first | DP.2-DETAIL | Approval request, asking for written approval. With `-PurgeProtectionApproved`, a notice of planned change that refers to the approval the client gave at build kickoff |
| 07 | Anonymous blob access disabled on the storage accounts where it carries no risk: DP.1-CONTAINERS listed every container (`ReadStatus` OK) and none is set to Blob or Container access. RESOURCES lists the container count of each account. Before Save, the steps check under Data storage > Containers that every container's anonymous access level still reads Private, and an account where one reads Blob or Container is left unchanged for the next pack. The rollback sets Allow Blob anonymous access back to Enabled, which applies within 30 seconds and leaves the containers as they are | DP.1-DETAIL, DP.1-CONTAINERS | Confirmation request, a notice that walks through why nothing breaks (every container is private, sign-in, shared access signature and account key access are unaffected, and a static website, whose `$web` container Azure serves anonymously whatever the setting, keeps working), says each account is checked again just before the change, offers to turn the setting back on straight away, and asks the client to confirm |
| 08 | HTTPS Only on App Service and Function apps | NB.4-DETAIL | Confirmation request, asking whether anything still calls the apps over HTTP |
| 09 | Encryption at host on the virtual machines that can take it. RESOURCES lists the VM ID of each machine, and before stopping a machine the steps check under Overview > JSON View that `properties.vmId` still reads that ID. A machine whose ID differs was deleted and created again under the same name after collection, so it is skipped and left for the next pack. Each machine changed is stopped for the change, and started again only if it was running when the change began, during the change and on rollback. The machines of a Flexible scale set that CR-15 changes are left to it | DP.4-ELIGIBILITY, DP.4-VMSS-ELIGIBILITY | Maintenance window request |
| 10 | Diagnostic logging remediated on the resources not compliant with the initiative: one remediation task for each assignment and policy, each resource listed once | DR.6-INITIATIVE, DR.6-NONCOMPLIANT | Notice of planned change, with the type of each resource, and that the resource logs add Log Analytics ingestion to the Sentinel workspace |
| 11 | Minimum TLS 1.2 on Azure Cache for Redis. Every cache has refused TLS 1.0 and 1.1 since April 1, 2025, and no minimum below 1.2 can be set since March 1, 2024, so this aligns the configuration and has no rollback | NB.6-PAAS-DETAIL | Notice of planned change, with no visible effect expected |
| 12 | Minimum TLS 1.2 on Service Bus namespaces. Service Bus accepts only TLS 1.2 and later, and a namespace takes only 1.2 or 1.3 as its minimum, so this aligns the configuration and has no rollback | NB.6-PAAS-DETAIL | Notice of planned change, with no visible effect expected |
| 13 | Minimum TLS 1.2 on Event Hubs namespaces. Event Hubs still documents namespaces that accept TLS 1.0 and 1.1 below a minimum of 1.2, so a client on an older version would be refused. The rollback sets the recorded version back | NB.6-PAAS-DETAIL | Confirmation request, asking whether anything still connects with TLS 1.0 or 1.1 |
| 14 | Minimum TLS 1.2 on Azure Cosmos DB accounts. Azure Cosmos DB retired TLS 1.0 and 1.1 on August 31, 2025 and accepts only TLS 1.2 as an account minimum, so this aligns the configuration and has no rollback | NB.6-PAAS-DETAIL | Notice of planned change, with no visible effect expected |
| 15 | Encryption at host on the virtual machine scale sets whose model can take it. The model is set from Cloud Shell, then each existing instance is stopped (deallocated), brought to the model (Upgrade on a Uniform instance, Settings > Disks > Additional settings on a Flexible one) and started again only if it was running. A scale set with an Automatic or Rolling upgrade policy may apply the model on its own, all at once or in batches, so the change runs inside the maintenance window and the availability impact says so. RESOURCES lists the unique ID of each scale set and the VM ID of each Flexible instance to change. Before the model is set, the steps check under Overview > JSON View that `properties.uniqueId` still reads the listed ID, and a scale set whose ID differs is left out of every step. The Flexible steps work through the instances the scale set holds when the change is made and change only an instance whose `properties.vmId` is listed for that scale set, so an instance that joined after collection, or one created again under a listed name, is skipped and left for the next pack. The rollback covers any instance created after the model was changed. AKS node pools are routed to a planned project in the index | DP.4-VMSS-ELIGIBILITY, DP.4-ELIGIBILITY | Maintenance window request |

Resources a change leaves out are named in the index notes:

- CR-04 leaves out App Service apps whose minimum TLS version Resource Graph returned empty, because App Service
  applies 1.2 when none is set. Check them in the portal if the value may be missing from Resource Graph.
- CR-07 leaves out FileStorage accounts, which hold no blob service, and every account it cannot show is safe to change:
  - an account with a container set to Blob or Container access, named with its public containers. Turning the
    setting off would stop those anonymous reads, so each container's owner confirms first that it serves no public
    content and the container is set to private. A later pack picks the account up for CR-07 once every container in
    it is private.
  - an account whose containers were not listed, because DP.1-CONTAINERS has no row for it or was not collected,
    failed or is unreadable. Recollect the pack.
  - an account whose containers DP.1-CONTAINERS could not list when it reads PARTIAL (a `ReadStatus` other than OK).
    Only an account read in full qualifies.

  When no account qualifies, CR-07 reads "No gaps found" and the notes still name the accounts left out.
- CR-01 assigns the initiative where no ATMO-MXDR policy state was found. An assignment made shortly before
  collection shows no state until its first compliance scan, so the index asks to confirm under Policy > Assignments
  first. When other subscriptions already have the initiative, CR-01 assigns per subscription even with
  `-ManagementGroup`, since an assignment at the group would overlap theirs. A PARTIAL DR.6-COVERAGE stops CR-01,
  since a subscription without the initiative cannot be told from one that was not read.
- CR-02 leaves out storage accounts that may serve NFS (NFS 3.0 on blob, or the FileStorage kind), because NFS
  mounts are refused once secure transfer is required. Add one only after confirming it hosts no NFS share.
- CR-09 leaves out every virtual machine that is not proven eligible: one that ever used Azure Disk Encryption, one
  with an Ultra Disk or Premium SSD v2 that uses 512e sectors and was created before May 13, 2023, one on a size without
  encryption at host support in its region, and one whose size support could not be read. The steps
  deallocate each machine before Azure checks the setting, so an ineligible machine would go down for nothing.
- CR-09 leaves out the machines of a Flexible scale set that CR-15 changes (DP.4-ELIGIBILITY names the scale set of
  each machine from collector 1.3.0), since CR-15 handles them with their scale set. The machines of a scale set
  that CR-15 leaves out stay in CR-09, where an eligible one is changed as a virtual machine. A pack from an earlier collector, or
  one whose DP.4-VMSS-ELIGIBILITY was not read, keeps them in CR-09, where they take the setting as virtual machines.
- CR-09 and CR-15 match each machine and scale set by the ID Azure gives it, never by its name alone (VmId in
  DP.4-ELIGIBILITY and UniqueId in DP.4-VMSS-ELIGIBILITY, from collector 1.4.0). A machine deleted and created again
  under the same name between collection and the change was never checked, and stopping it for a setting Azure then
  rejects is the downtime these changes avoid. The index explains that a machine or scale set whose ID differs when the
  change runs is skipped and left for the next pack. One whose ID was not read is left out of the change request with
  a note, and a Flexible scale set with such a machine is left out of CR-15. A Flexible scale set that CR-15 leaves out
  for its own missing unique ID keeps its checked machines in CR-09. On a pack from before collector 1.4.0, CR-09
  and CR-15 read "Needs recollection with CyberSOC collector 1.4.0 or later" whenever they have a machine or scale set
  to change. A rerun of the read-only collector is the only way to get the IDs, and a name-only fallback would bring
  back the gap the IDs close. The notes on machines and scale sets that are not eligible, and the AKS note, are kept.
- CR-15 leaves out every scale set that is not proven eligible, on the same rules as CR-09: Azure Disk Encryption
  on the model, an Ultra Disk or Premium SSD v2 in the model of a scale set created before May 13, 2023, a size
  without support or whose support could not be read. A Flexible scale set is left out too when one of its machines
  without encryption at host is not eligible, or when DP.4-ELIGIBILITY cannot prove the list of them complete: only an
  OK or EMPTY result shows that a machine missing from it already has encryption at host, so a PARTIAL one (a
  truncated read or an unread size list) leaves every Flexible scale set out. A Flexible scale set
  without a model has nothing to set, so its machines stay in CR-09.
- AKS node pools (a scale set in the node resource group of a cluster, or tagged `aks-managed-`) get no change
  request. AKS sets encryption at host only when a node pool is created, so an existing pool is replaced: a new node
  pool created with `--enable-encryption-at-host`, its workloads moved across and the old pool removed. That needs
  capacity, disruption budgets and the pool settings agreed with the client, so the index names each cluster and
  node pool and routes them to a planned project instead of a low-impact change.

## How each change request is written

The sections follow the template headings, in order, so each one pastes into the change request form.

- The change description and purpose are two sentences at most. Availability, user experience and dependencies are
  one sentence each.
- Resources are grouped by subscription, named with its display name from P0.7 and its ID, with the resource group
  and the current setting of each resource, so the rollback plan can return a resource to it.
- DR Impact reads Not a DR Client, or N/A - No DR impact with `-DrClient`. The DR plan follows it. Encryption at host
  is the exception on a DR client: Azure Site Recovery does not carry the setting to failover virtual machines, so
  the DR plan adds the post-failover step to the DR Playbook and asks for the evidence before the change is closed.
  CR-15 does the same for the instances of a Flexible scale set, and keeps the standard DR text for Uniform ones,
  which Site Recovery does not replicate.
- Mitigation reads "If changes need to be reverted, follow the rollback plan." on every change except purge
  protection, which cannot be disabled once enabled. That change explains the soft delete retention instead, and its
  rollback plan says no rollback is possible and how to recover a deleted vault. The minimum TLS changes for Azure
  SQL, Redis, Service Bus and Cosmos DB keep the standard mitigation, and their rollback plans say no rollback is
  available or needed, because the service no longer takes a lower minimum and already refuses TLS 1.0 and 1.1.
- The implementation plan holds only the steps that make the change, in the Azure portal. Encryption at host also
  registers the EncryptionAtHost feature on each subscription from Cloud Shell, since the portal has no other path
  for it. Each register and status command names its subscription, so the plan waits until the feature reads
  Registered on every subscription, not only the one Cloud Shell was left on. CR-15 also sets the scale set model
  from Cloud Shell with `az vmss update --set virtualMachineProfile.securityProfile.encryptionAtHost=true`, each
  subscription, resource group and scale set name quoted for Bash (a resource group name may hold parentheses), because
  Microsoft Learn documents only the CLI and PowerShell for an existing scale set, and its rollback sets it back to
  false the same way.
- The testing plan checks the setting in the Azure portal and nothing else. CR-15 reads the model from JSON View on
  the scale set Overview.
- References are Microsoft Learn pages only.
- The notification list is left empty to fill in.
- Every change request writes a client email (`CR-NN-<change>.email.txt`). The generator stops before writing
  anything when a change request has none, and the Pester suite fails when any change request from CR-01 to CR-15
  is written without one. A new change request picks one of the two kinds of email below.

Every client email is written in the first person singular, explains the change and what it means for the client,
and lists the affected resources by subscription. There are two kinds:

- **Approval, confirmation or maintenance window request,** for a change that needs the client first: CR-06
  (purge protection, which cannot be undone), CR-07 (anonymous blob access), CR-08 (HTTPS only), CR-09 and CR-15
  (encryption at host, which restarts each machine) and CR-13 (minimum TLS 1.2 on Event Hubs, which still accepts
  older clients). The change waits for the reply. The purge protection email lists the vaults by subscription with
  the soft delete retention period of each, explains that purge protection cannot be turned off and that a deleted
  vault, key, secret or certificate is kept for that period, cannot be purged early and keeps its name until the
  period ends, and asks for the client's written approval before the change is scheduled.
- **Notice of planned change,** for every other change: CR-01 to CR-05, CR-10, CR-11, CR-12 and CR-14, and CR-06
  with `-PurgeProtectionApproved`. It says what changes and why, lists the resources by subscription, says what the
  client should expect and why (usually no visible effect, because the platform already refuses what the setting
  turns off), gives the planned date and asks the client to raise any concern a week before it. CR-01 and CR-10
  send resource logs to the client's Sentinel workspace, so their notices say that this adds Log Analytics ingestion,
  billed by volume, and that the Activity log is ingested at no charge. The CR-06 notice refers to the approval
  given at build kickoff and repeats that purge protection cannot be turned off. The index names the notices with
  their dates. The change goes ahead on its planned date unless the client raises a concern.

Each claim in the emails was checked on Microsoft Learn: secure transfer rejects HTTP requests and SMB without
encryption (Require secure transfer to ensure secure connections), the TLS retirement dates and minimums of each
service (the pages each change request cites), the Log Analytics ingestion charge for resource logs sent through
diagnostic settings (Azure Monitor cost and usage), and the Activity log collected at no charge (Azure Monitor data
sources, Microsoft Sentinel free data sources).

Every change request, email and the index keep to the copy rules: no semicolons, arrows, emoji or angle brackets, and
the greater-than sign only in navigation steps such as Settings > Configuration. The CSV is tracking data and carries
each resource ID exactly as Azure has it. Values read from the pack are cleaned of every character the check
rejects, and a file that still breaks a rule stops the run before any file is written.

## Output

| File | Contents |
|---|---|
| `CR-NN-<change>.txt` | One change request |
| `CR-NN-<change>.email.txt` | The client email for that change, subject line first |
| `00-index.md` | Every change with its status and files, and notes on the resources left out |
| `change-requests.csv` | One row per resource: CR, Change, Subscription, ResourceGroup, Resource, CurrentSetting, ResourceId |

Each change reports one of these statuses in the index: change request and client email, no gaps found, not
collected with the manifest status, result file unreadable, or needs recollection with CyberSOC collector 1.1.0 or
later (1.2.0 or later for CR-11 to CR-14, 1.3.0 or later for CR-15, and 1.4.0 or later for CR-09 and CR-15 when they
have a machine or scale set to change). A result the manifest reads as OK or PARTIAL whose file is missing, empty or not valid JSON is unreadable, never
read as no gaps. A change request that also reads a result beyond its sources (DR.6-COVERAGE and P0.5 for CR-01,
DR.6-NONCOMPLIANT for CR-10, DP.1-CONTAINERS for CR-07, DP.4-VMSS-ELIGIBILITY for CR-09 on a 1.3.0 pack) reads "partial
collection scope" when that result
is PARTIAL, and gets a note in the index when it was not collected or is unreadable.

Every file is built and checked against the copy rules before the folder is touched, so a run that stops leaves the
earlier files as they were. The per-resource
results (P0.7, NB.4-DETAIL, NB.5-DETAIL, NB.6-DETAIL, DP.1-DETAIL, DP.2-DETAIL, DP.4-ELIGIBILITY,
DR.6-COVERAGE, DR.6-NONCOMPLIANT) were added in collector 1.1.0, and NB.6-PAAS-DETAIL, which lists the Redis caches,
Service Bus and Event Hubs namespaces and Cosmos DB accounts below TLS 1.2 for CR-11 to CR-14, in 1.2.0.
DP.4-VMSS-ELIGIBILITY, which lists the scale sets without encryption at host for CR-15, and the ScaleSet column of
DP.4-ELIGIBILITY were added in 1.3.0, and the VmId column of DP.4-ELIGIBILITY and the UniqueId column of
DP.4-VMSS-ELIGIBILITY in 1.4.0. Their queries are in section 6 of the CyberSOC Monthly Report Runbook.

## Validation

```powershell
Invoke-Pester -Path tests/New-CyberSocChangeRequests.Tests.ps1
```

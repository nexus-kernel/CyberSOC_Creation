# Hardening change requests

`New-CyberSocChangeRequests.ps1` turns a finished evidence pack into the change requests for the security hardening
items that can be applied without affecting operations, laid out on the change request template. The changes that
need the client first also get a client email, drafted and ready to send. The files name client resources, so they
stay internal until they are sent.

## Generate from an existing evidence pack

```powershell
./New-CyberSocChangeRequests.ps1 -EvidencePath ./CyberSOC-Evidence_Contoso_2026-09_20261003-090000
```

Writes `05-change-requests` into the pack. Offline only. Nothing in the pack is changed.

| Parameter | Effect |
|---|---|
| `-OutputPath <folder>` | Writes the files elsewhere |
| `-DrClient` | DR Impact reads N/A - No DR impact instead of Not a DR Client, and the encryption at host change adds the DR Playbook step that Azure Site Recovery needs |
| `-SentinelWorkspace <name>` | The workspace the diagnostic logging initiative sends to. Defaults to the pack's workspace when it holds one, otherwise the change names the client Sentinel workspace without its name |
| `-ClientContact <name>` | The name the client emails open with. Without it they open with Hello |
| `-SenderName <name>` | The name under the sign-off of the client emails |

Run it again after a recollection. It replaces the change requests it wrote before, removes the ones the pack no
longer supports, and leaves every other file in the folder alone.

## The changes

Each change is written only when the pack shows resources still to fix. The numbers stay the same from run to run.

| CR | Change | Evidence | Client email |
|---|---|---|---|
| 01 | Diagnostic logging through ATMO-MXDR-DIAG-TOSENT. Assigns the initiative when it is not assigned (DR.6-INITIATIVE is EMPTY), with the resource types it covers counted from P0.5. Otherwise runs a remediation task for each policy the listed resources fail | DR.6-INITIATIVE, DR.6-NONCOMPLIANT, P0.5 | No |
| 02 | Secure transfer required on storage accounts | DP.1-DETAIL | No |
| 03 | Minimum TLS 1.2 on storage accounts. Azure Storage has refused TLS 1.0 and 1.1 since February 3, 2026, so this aligns the configuration | DP.1-DETAIL | No |
| 04 | Minimum inbound TLS 1.2 on App Service and Function apps. App Service refuses TLS 1.0 and 1.1 from May 31, 2027 | NB.5-DETAIL | No |
| 05 | Minimum TLS 1.2 on Azure SQL logical servers. Azure SQL retired TLS 1.0 and 1.1 on August 31, 2025 | NB.6-DETAIL | No |
| 06 | Purge protection on key vaults | DP.2-DETAIL | No |
| 07 | Anonymous blob access disabled on storage accounts, naming the containers open to anonymous read today | DP.1-DETAIL, DP.1-CONTAINERS | Yes |
| 08 | HTTPS Only on App Service and Function apps | NB.4-DETAIL | Yes |
| 09 | Encryption at host on virtual machines, which needs a stop and start of each | DP.4-DETAIL | Yes, asking for a maintenance window |

Resources a change leaves out are named in the index notes:

- CR-02 leaves out storage accounts that may serve NFS (NFS 3.0 on blob, or the FileStorage kind), because NFS
  mounts are refused once secure transfer is required. Add one only after confirming it hosts no NFS share.
- CR-09 leaves out scale sets. They take encryption at host through their model and an instance update, and AKS
  node pools through the node pool, so they need their own change.

## How each change request is written

The sections follow the template headings, in order, so each one pastes into the change request form.

- The change description and purpose are two sentences at most. Availability, user experience and dependencies are
  one sentence each.
- Resources are grouped by subscription, named with its display name from P0.7 and its ID, with the resource group
  and the current setting of each resource, so the rollback plan can return a resource to it.
- DR Impact reads Not a DR Client, or N/A - No DR impact with `-DrClient`. The DR plan follows it. Encryption at host
  is the exception on a DR client: Azure Site Recovery does not carry the setting to failover virtual machines, so
  the DR plan adds the post-failover step to the DR Playbook and asks for the evidence before the change is closed.
- Mitigation reads "If changes need to be reverted, follow the rollback plan." on every change except purge
  protection, which cannot be disabled once enabled. That change explains the soft delete retention instead, and its
  rollback plan says no rollback is possible and how to recover a deleted vault.
- The implementation plan holds only the steps that make the change, in the Azure portal. Encryption at host also
  registers the EncryptionAtHost feature on each subscription from Cloud Shell, since the portal has no other path
  for it.
- The testing plan checks the setting in the Azure portal and nothing else.
- References are Microsoft Learn pages only.
- The notification list is left empty to fill in.

The client emails are written in the first person, explain the change and what it means for the client, list the
affected resources and ask for a confirmation or a maintenance window before anything is scheduled.

Every file keeps to the copy rules: no semicolons, arrows, emoji or angle brackets, and the greater-than sign only in
navigation steps such as Settings > Configuration. Values read from the pack are cleaned the same way, and a file that
breaks a rule stops the run before it is written.

## Output

| File | Contents |
|---|---|
| `CR-NN-<change>.txt` | One change request |
| `CR-NN-<change>.email.txt` | The client email for that change, subject line first |
| `00-index.md` | Every change with its status and files, and notes on the resources left out |
| `change-requests.csv` | One row per resource: CR, Change, Subscription, ResourceGroup, Resource, CurrentSetting, ResourceId |

Each change reports one of these statuses in the index: a change request (and client email), no gaps found, not
collected with the manifest status, or needs recollection with CyberSOC collector 1.1.0 or later. The per-resource
results (P0.7, NB.4-DETAIL, NB.5-DETAIL, NB.6-DETAIL, DP.1-DETAIL, DP.2-DETAIL, DR.6-NONCOMPLIANT) were added in
that version. Their queries are in section 6 of the CyberSOC Monthly Report Runbook.

## Validation

```powershell
Invoke-Pester -Path tests/New-CyberSocChangeRequests.Tests.ps1
```

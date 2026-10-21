# Hardening change requests

`New-CyberSocChangeRequests.ps1` turns a finished evidence pack into the change requests for the security hardening
items that can be applied without affecting operations, laid out on the change request template. Every change
request also gets a client email, drafted and ready to send, that asks for the client's approval. No change is
scheduled until the client approves it. The files name client resources, so they stay internal until they are sent.

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
| `-PurgeProtectionApproved` | The client approved purge protection at build kickoff. The CR-06 email refers to that approval and asks the client to confirm it still stands and to approve the proposed date, and the index notes the approval |
| `-ChangeDate <date>` | The proposed date the client emails ask the client to approve. Every email asks for a reply by a week before it. Defaults to two weeks after the build date, and must be at least eight days after it |
| `-AdminRuleOpen <resource ID:port>` | The virtual machines whose effective security rules show an Azure Virtual Network Manager security admin rule with Always Allow on 22, 3389, 5985 or 5986 from an internet source, each as the resource ID of the virtual machine followed by `:port`, such as `/subscriptions/<subscription>/resourceGroups/rg-web/providers/Microsoft.Compute/virtualMachines/vm-web01:3389`. The resource ID names each machine once, since a machine name is unique only within its resource group, and the email, change request and index name the machine with its resource group and subscription. CR-16 cannot close those ports, so its email says a central network policy keeps them open and asks who manages it, and the change request and the index name the machines |
| `-DefenderEndpointPlan <plan>` | The Defender for Endpoint plan read in the Defender portal under Settings > Endpoints > Licenses: Plan1, Plan2, Business or Mixed. Replaces the reading the collection recorded (`Licensing` in `00-parameters.json`). The licensing check takes it for the plan and names any disagreement with what the API reads show. See [Licensing gate](#licensing-gate) |

Run it again after a recollection, or on its own to write the files again with another contact, sender or proposed
date, or on the day the emails are sent so their dates start from that day. The collector does not take
`-ChangeDate` or `-AdminRuleOpen`, so a collection run always proposes a date two weeks after the build. To propose another date, run
the generator again on the pack with it, for example
`./New-CyberSocChangeRequests.ps1 -EvidencePath <pack> -ClientContact 'Dana' -SenderName 'Scott' -ChangeDate 2026-11-16`. It replaces the change requests it wrote before, removes the ones the pack no
longer supports, and leaves every other file in the folder alone.

## The changes

Each change is written only when the pack shows resources still to fix. The numbers stay the same from run to run.

| CR | Change | Evidence | Client email |
|---|---|---|---|
| 01 | Diagnostic logging initiative ATMO-MXDR-DIAG-TOSENT assigned on every subscription. When it has no policy state anywhere (DR.6-INITIATIVE is EMPTY) it is assigned once at the management group named with `-ManagementGroup`, or at each subscription. When some subscriptions already have it, it is assigned at each subscription without a state (DR.6-COVERAGE). The covered resource types are counted from P0.5 | DR.6-INITIATIVE, DR.6-COVERAGE, P0.5 | Yes, approval request |
| 02 | Secure transfer required on storage accounts | DP.1-DETAIL | Yes, approval request |
| 03 | Minimum TLS 1.2 on storage accounts. Azure Storage has refused TLS 1.0 and 1.1 since February 3, 2026, so this aligns the configuration | DP.1-DETAIL | Yes, approval request |
| 04 | Minimum inbound TLS 1.2 on App Service and Function apps, on the site (Minimum Inbound TLS Version) and on its SCM (Kudu) site (SCM Minimum Inbound TLS Version, under Settings > Configuration > General settings), each set only where it is below 1.2, so an app whose site minimum is already 1.2 gets only the SCM step. Before changing a value, the steps read it under Settings > Configuration > General settings, and a value that already shows 1.2 or later has changed since collection, so it is left as it is and noted, never lowered. App Service refuses TLS 1.0 and 1.1 on the app endpoint and the SCM endpoint from May 31, 2027. RESOURCES and the CSV show both recorded values, the testing plan checks both in the portal, and the rollback sets each value the change made back to its recorded version, never a fixed 1.0. The email explains the SCM site once, as the deployment and management endpoint that tools such as zip deploy, Web Deploy and local Git reach, and asks before the approval whether any deployment tool, build agent or script still reaches it over TLS 1.0 or 1.1. On a pack collected before 1.13.0, which does not record the SCM value, CR-04 writes the site part only | NB.5-DETAIL | Yes, approval request |
| 05 | Minimum TLS 1.2 on Azure SQL logical servers. Azure SQL retired TLS 1.0 and 1.1 on August 31, 2025 | NB.6-DETAIL | Yes, approval request |
| 06 | Purge protection on key vaults, with the soft delete retention period of each vault. Purge protection cannot be disabled once enabled, so the client approves it in writing first | DP.2-DETAIL | Yes, approval request |
| 07 | Anonymous blob access disabled on the storage accounts where it carries no risk: DP.1-CONTAINERS listed every container (`ReadStatus` OK) and none is set to Blob or Container access. RESOURCES lists the container count of each account. Before Save, the steps check under Data storage > Containers that every container's anonymous access level still reads Private, and an account where one reads Blob or Container is left unchanged for the next pack. The rollback sets Allow Blob anonymous access back to Enabled, which applies within 30 seconds and leaves the containers as they are. An account with a container set to Blob or Container waits for CR-18 | DP.1-DETAIL, DP.1-CONTAINERS | Yes, approval request |
| 08 | HTTPS Only on App Service and Function apps | NB.4-DETAIL | Yes, approval request |
| 09 | Encryption at host on the virtual machines that can take it. RESOURCES lists the VM ID of each machine, and before stopping a machine the steps check under Overview > JSON View that `properties.vmId` still reads that ID. A machine whose ID differs was deleted and created again under the same name after collection, so it is skipped and left for the next pack. Each machine changed is stopped for the change, and started again only if it was running when the change began, during the change and on rollback. The machines of a Flexible scale set that CR-15 changes are left to it | DP.4-ELIGIBILITY, DP.4-VMSS-ELIGIBILITY | Yes, approval request |
| 10 | Diagnostic logging remediated on the resources not compliant with the initiative: one remediation task for each assignment and policy, each resource listed once | DR.6-INITIATIVE, DR.6-NONCOMPLIANT | Yes, approval request |
| 11 | Minimum TLS 1.2 on Azure Cache for Redis. Every cache has refused TLS 1.0 and 1.1 since April 1, 2025, and no minimum below 1.2 can be set since March 1, 2024, so this aligns the configuration and has no rollback | NB.6-PAAS-DETAIL | Yes, approval request |
| 12 | Minimum TLS 1.2 on Service Bus namespaces. Service Bus accepts only TLS 1.2 and later, and a namespace takes only 1.2 or 1.3 as its minimum, so this aligns the configuration and has no rollback | NB.6-PAAS-DETAIL | Yes, approval request |
| 13 | Minimum TLS 1.2 on Event Hubs namespaces. Event Hubs still documents namespaces that accept TLS 1.0 and 1.1 below a minimum of 1.2, so a client on an older version would be refused. The rollback sets the recorded version back | NB.6-PAAS-DETAIL | Yes, approval request |
| 14 | Minimum TLS 1.2 on Azure Cosmos DB accounts. Azure Cosmos DB retired TLS 1.0 and 1.1 on August 31, 2025 and accepts only TLS 1.2 as an account minimum, so this aligns the configuration and has no rollback | NB.6-PAAS-DETAIL | Yes, approval request |
| 15 | Encryption at host on the virtual machine scale sets whose model can take it. The model is set from Cloud Shell, then each existing instance is stopped (deallocated), brought to the model (Upgrade on a Uniform instance, Settings > Disks > Additional settings on a Flexible one) and started again only if it was running. A scale set with an Automatic or Rolling upgrade policy may apply the model on its own, all at once or in batches, so the change runs inside the maintenance window and the availability impact says so. RESOURCES lists the unique ID of each scale set and the VM ID of each Flexible instance to change. Before the model is set, the steps check under Overview > JSON View that `properties.uniqueId` still reads the listed ID, and a scale set whose ID differs is left out of every step. The Flexible steps work through the instances the scale set holds when the change is made and change only an instance whose `properties.vmId` is listed for that scale set, so an instance that joined after collection, or one created again under a listed name, is skipped and left for the next pack. The rollback covers any instance created after the model was changed. AKS node pools are routed to a planned project in the index | DP.4-VMSS-ELIGIBILITY, DP.4-ELIGIBILITY | Yes, approval request |
| 16 | Internet-facing RDP, SSH and WinRM rules closed: each allow inbound rule open to any address, Internet, 0.0.0.0/0 or ::/0 on 22, 3389, 5985 or 5986 over TCP or any protocol, on a workload subnet or network interface. The replacement path the client agrees goes in first: just-in-time VM access (Defender for Cloud > Workload protections > Just-in-time VM access), which needs Defender for Servers Plan 2 on the subscription, or Azure Bastion (Connect > Bastion on the virtual network) for RDP and SSH. Bastion provides RDP and SSH sessions only (What is Azure Bastion), so a rule that opens WinRM (5985 or 5986) keeps WinRM only through just-in-time VM access or named source addresses, never Bastion, and is left unchanged where the client still needs WinRM and neither is agreed. The existing rules keep priority over the just-in-time deny rules until they are removed. Where Bastion is the path, every network security group of the machines gets an allow on 22 and 3389 from the AzureBastionSubnet address range ahead of any deny rule, and a Bastion session is opened before any rule changes. A rule whose source is Any, 0.0.0.0/0 or ::/0 also matches private addresses, so its management ports first get an allow from the private ranges the client confirms in reply to the email (the virtual network address spaces, peered networks and on-premises ranges), entered as CIDR blocks and never as a service tag, unless the client confirmed nothing connects from them. The service tag for the virtual network also holds the prefixes of user-defined routes, so with a forced-tunneling `0.0.0.0/0` route it would keep the ports open to the internet. A broad rule is left unchanged until the client confirms one or the other. Then each rule is deleted, or narrowed to the source addresses the client named, and a rule that also allows other ports loses only the management ports: when addresses were named, its management ports move to a new rule from those addresses, so its other ports keep the source they have. Last, the effective security rules of each network interface the rules applied to (Virtual machines > the machine > Networking > the network interface > Effective security rules, downloaded as a file, since the page shows only the first 50 rules) show the source prefixes behind every allow on those ports. A port is still open where an allow lists `0.0.0.0/0`, `::/0` or other public prefixes nobody named (such as `0.0.0.0/1` and `128.0.0.0/1`), no deny from Any, `0.0.0.0/0`, `::/0` or Internet on that port comes first in its group, and the other group on the path (subnet or network interface) also lets the connection through. The default virtual network rule behind a forced-tunneling route is the usual case. A TCP deny on the open management ports from the Internet service tag then goes in at a custom priority (100 to 4096) after the allows of its group for named addresses or sources the client already allows on purpose and, where the open allow is a custom rule in the same group, ahead of it. Default rules (65000 and above) always come after it. The ports of a rule the change left unchanged get no deny on the interfaces behind it and are noted with that rule, while the other open management ports there are still denied, and a rule for another protocol left for review keeps working. The network interfaces in a subnet come from the Connected devices page of its virtual network, a machine just-in-time VM access covers is checked only for security admin rules since its deny already stops the internet once the groups decide, and a stopped machine, whose effective rules cannot be read, gets the deny without the check and has its security admin rules read on the Security admin configurations tab of its virtual network (Settings > Network Manager). The effective rules also list the Azure Virtual Network Manager security admin rules applied to the virtual network, which apply before both groups: the first that matches decides, Always Allow lets the connection in whatever the groups say, Deny stops it, and Allow passes it on to the groups. Where the first admin rule that matches an internet source on a port is an Always Allow, no network security group change can close the port, so the operator records the admin rule in the change record, escalates it to whoever owns the Virtual Network Manager configuration and never counts the port as closed, and the deny still goes in so it applies once the admin rule is gone. The index says such a machine is outside what CR-16 can close, and `-AdminRuleOpen` names it in the email, the change request and the index. The testing plan repeats that check. RESOURCES lists every property of each rule, and the path that fits each subscription from P0.3. The rollback recreates the rule from those properties, also in the CSV, ahead of any just-in-time deny rule, and deletes the rules the change added, the deny from the Internet service tag included | NB.2-DETAIL, P0.3 | Yes, approval request |
| 17 | Plain FTP turned off on App Service and Function apps: the FTP state set to FTPS only, or to Disabled only where the client confirms no tool, process or person uses FTP or FTPS on the app, to upload files or to download files or logs. Only an app whose state reads `AllAllowed` is changed. Before changing an app, the steps read its FTP state under Settings > Configuration > General settings, and an app that no longer shows the recorded All allowed has changed since collection, so it is skipped and left for the next pack. FTPS only does not support TLS 1.0 or 1.1, so an app whose minimum inbound TLS version reads 1.0 or 1.1 is left unchanged until CR-04 sets 1.2, unless the client chooses Disabled. RESOURCES and the CSV show that minimum beside the FTP state. The rollback sets each app back to All allowed, the recorded state | NB.5-FTPS-DETAIL | Yes, approval request |
| 18 | Blob containers set to private access: each container set to Blob or Container in a storage account that allows anonymous access, so anyone can read it today, set to Private under Data storage > Containers > Change access level, grouped by subscription and account. RESOURCES has one line per account with its containers counted and named, each with its recorded level, and the CSV one row per container. Before the change, the steps read Allow Blob anonymous access under Settings > Configuration and skip an account that now shows Disabled, since its containers can no longer be read anonymously and the portal cannot change their level, then read each listed container and skip one that no longer shows its recorded level or that the client asked to keep out. A container opened after collection is noted for the next pack, never changed. Setting a container to Private stops anonymous reads straight away, which the purpose and the email say. The static website container `$web` is left out, since its site is served from the web endpoint whatever its level. RESOURCES explains the order with CR-07: CR-07 takes only an account with no container set to Blob or Container, so a later pack picks each account up for CR-07 once its containers read Private. The rollback sets each container back to its recorded level, which Microsoft Learn allows only while the account allows anonymous access, so after CR-07 it needs that setting enabled again, which reopens every public container in the account | DP.1-CONTAINERS-DETAIL, DP.1-CONTAINERS, DP.1-DETAIL | Yes, approval request |
| 19 | Roles removed from disabled accounts: every Azure role assignment, at management group, subscription, resource group, resource or root scope, and every Microsoft Entra role assignment, standing, time-bound, activated or eligible, that a user account the pack records as disabled holds, assigned to the account itself or through a group. A role assigned to the account is removed at its scope. A role held through a group is taken away by removing the account from the group it sits in, the role group itself or a group nested in it, which the pack records from collector 1.10.0 (`MemberOfId`, `GroupPath`), so the group and its other members keep the role. A group whose members a rule decides (dynamic membership) or that is synced from on-premises Active Directory cannot lose a member here, so its roles stay and the index names them. RESOURCES lists the Azure assignments by subscription, then the management groups and the root scope above them, the Entra assignments on their own, each with the account and its object ID, the role and its definition ID, the scope and the assignment ID, and then the group memberships removed, each with the group the account leaves, the role group it is nested in where it is, and the roles that group holds. Before removing anything, the steps open the account under Microsoft Entra ID > Users and read Account status, and an account turned back on since collection, or one the client asked to keep, is left unchanged and noted. An Azure assignment is removed under Access control (IAM) > Role assignments at the scope where it was made, and one at the root scope, which the portal cannot remove, with `az role assignment delete` from Cloud Shell. An Entra assignment is removed under Roles and administrators, or from its administrative unit, and an eligible one in Privileged Identity Management. An Entra role scoped to an administrative unit, or to a single application or other object (a directory scope of the form `/<object ID>`), is removed and restored from that unit or object, never from the tenant-wide list, which would restore it across the tenant. A group membership is removed under Groups > All groups > the group > Members > Remove, after confirming that each role group on the line still holds its roles (Azure role assignments or Assigned roles) and that each nested group is still a member of the one above it (Group memberships), since a membership that still carries any role on its line is removed and one whose every role is gone, or whose chain is broken, stays, and restored with Add members. The rollback recreates each assignment from its recorded role, scope and account, which the CSV carries in full, one row per assignment and one per membership (resource ID `/groups/<group>/members/<account>/$ref`), with any ABAC condition and its version exactly as Azure has them. A condition narrows what the role grants, so an assignment recorded with one is recreated with it: on the Conditions tab in the code editor, or with `az role assignment create --condition "$(cat condition.txt)"` from Cloud Shell in Bash at a management group or root scope, where the portal cannot add a condition. The command reads the condition from a file, so the shell never expands a token such as `$key_case_sensitive$`. Each assignment matches one rollback step only: without a condition below the root, with a condition at any scope, or without a condition at the root. Only one side is written when the other could not be read, and the index says which side is missing and why | IA.15-DISABLED, IA.15-RBAC, IA.15-ENTRA | Yes, approval request, with the accounts and their roles in `CR-19-disabled-account-roles.email.csv` to attach |

Resources a change leaves out are named in the index notes:

- CR-04 leaves out App Service apps whose minimum TLS version Resource Graph returned empty, because App Service
  applies 1.2 when none is set. Check them in the portal if the value may be missing from Resource Graph. An app
  whose SCM minimum is below 1.2 is still in CR-04 for its SCM part, and the note says so. Apps whose SCM minimum
  Resource Graph returned empty are left out of the SCM part the same way, since App Service applies 1.2 to the SCM
  site too. The notes also say, unless NB.5 shows no App Service site, that deployment slots, which have both values
  of their own, are not read and so not covered. On a pack collected before 1.13.0 a note says the SCM part needs
  recollection, and an empty list reads "No site gaps found, the SCM part needs recollection with CyberSOC collector
  1.13.0 or later", since the older list left out a site at 1.2 whatever its SCM minimum.
- CR-17 leaves out App Service apps whose FTP state Resource Graph returned empty, or as a value Microsoft Learn does
  not list (only `AllAllowed`, `FtpsOnly` and `Disabled`). Learn documents no state App Service applies when none is
  set, so such an app may still accept plain FTP: the note names each one for a check in the portal. When only those
  remain, CR-17 reads "Only apps without a recorded FTP state remain, see the notes". Its notes also say, unless NB.5 shows
  no App Service site, that deployment slots, which have a configuration of their own, are not read and so not covered, name the apps in
  CR-17 whose minimum TLS version is below 1.2, and point to FTP Basic Auth Publishing Credentials as a possible
  follow-up that is not part of the change.
- CR-07 leaves out FileStorage accounts, which hold no blob service, and every account it cannot show is safe to change:
  - an account with a container set to Blob or Container access, named with its public containers. Turning the
    setting off would stop those anonymous reads, so CR-18 asks each container's owner to confirm first that it serves
    no public content, and sets the container to private. A later pack picks the account up for CR-07 once every
    container in it is private. CR-18 never changes the static website container (`$web`), so the note says so when one
    of these accounts also has a public `$web`, and an account whose only public container is `$web` gets a note of its
    own: `$web` is set to Private on its own, as the CR-18 notes say, before the account can reach CR-07.
  - an account whose containers were not listed, because DP.1-CONTAINERS has no row for it or was not collected,
    failed or is unreadable. Recollect the pack.
  - an account whose containers DP.1-CONTAINERS could not list when it reads PARTIAL (a `ReadStatus` other than OK).
    Only an account read in full qualifies.

  When no account qualifies, CR-07 reads "No gaps found" and the notes still name the accounts left out.
- CR-18 changes only the containers anyone can read today. Its notes name, each account with its containers counted:
  - the static website containers (`$web`) set to Blob or Container. A static website is served from the web endpoint
    of its account whatever the level of `$web` (Static website hosting in Azure Storage), so setting it to Private
    would not close the site, only the copy of its files on the blob endpoint. An account that allows anonymous
    access stays out of CR-07 until `$web` is private too.
  - the containers set to Blob or Container in an account that blocks anonymous access. The account setting keeps them
    closed, and the portal cannot change a container's level while the account blocks anonymous access, so they are
    left as they are, to be set to Private by any change that relaxes the account setting.
  - the accounts DP.1-CONTAINERS could not list (a `ReadStatus` other than OK), whose containers are not in the
    detail. Recollect the pack.
  - the FileStorage accounts in DP.1-DETAIL, which hold no blob service.

  When CR-18 is written, a note also says how to see what still reads each account without signing in before it is
  sent: the Transactions metric of the Blob namespace filtered on Authentication Anonymous, and `StorageBlobLogs`
  with `AuthenticationType` Anonymous where the account sends its logs to the workspace. When only `$web` or blocked
  containers remain, CR-18 reads "Only containers the account setting already blocks, or static website containers,
  remain, see the notes".
- CR-19 lists only a role of an account IA.15-DISABLED records as disabled, whatever the role results hold, so an
  enabled account is never listed. A role assigned to the account itself is removed. A role held through a group is
  taken away by removing the account from the group it sits in, the role group or a group nested in it, which the
  pack records from collector 1.10.0, so the group and its other members keep the role. Its notes name:
  - each account removed from a group, with the group it leaves, the role group that group is nested in where it is,
    and the roles the group holds.
  - the roles held through a group whose members CR-19 cannot change, a dynamic membership group, whose members a
    rule decides, or a group synced from on-premises Active Directory, left unchanged for a review with the group
    owner. On a pack collected before 1.10.0, which does not record the group each account sits in, every role held
    through a group is left unchanged and the note asks for a recollection.
  - that the accounts and their roles are in `CR-19-disabled-account-roles.email.csv`, to attach to the email.
  - the accounts synced from on-premises Active Directory, whose disabled state comes from Active Directory, so
    re-enabling one there turns it back on at the next sync, without the roles.
  - an account holding Global Administrator, Privileged Role Administrator, Privileged Authentication Administrator or
    a role at the Azure root scope, to ask the client whether it is an emergency access account before sending.
  - when IA.15-ENTRA could not see eligible assignments ("Eligible assignments not visible", for a missing
    RoleManagement.Read.Directory or a failed schedule read), that only active Entra assignments are listed, that an
    activated one reads as Standing when no Activated or Time-bound row shows the active schedules were read, and that
    an account whose only roles are eligible is missing.
  - each role listed as Activated with no Eligible row for the same account, role and directory scope. The CSV holds
    only the activation's expiry, so implementation step 6 has the eligible assignment's start, end, role and directory
    scope recorded from Privileged Identity Management in the change record before it is removed, and leaves one held
    by a group in place. The rollback restores it from that record, never as permanent unless the record shows no end
    date. An Activated role with its Eligible row is removed and restored through that row, as before.
  - when the Azure side was read through Lighthouse, that Resource Graph showed the managing tenant's delegations, so
    Azure roles may be missing. Whenever the Azure side was read, that only the subscriptions in the pack and the
    management groups and root scope above them were read, and that Resource Graph never holds the eligible
    assignments of Privileged Identity Management for Azure resources.
  - when one side could not be read, which side is missing and the collector's reason, such as the permission it
    needs. That side is unknown, not a zero.
  - that disabled service principals are not read.

  The status reads "Not collected (IA.15-DISABLED UNAVAILABLE)" when the accounts could not be read, "No gaps found in
  the Azure roles, Microsoft Entra roles not collected (...), see the notes" when one side is clean and the other was
  not read, "Only roles held through groups whose members cannot be changed here remain, see the notes" when the only
  roles reach the accounts through dynamic or synced groups, "Only roles held through groups remain, see the notes"
  on a pack collected before 1.10.0 with nothing assigned directly, and "No roles
  found in what was read, ... read in part, see the notes" when a side read in part returned nothing, so a partial
  read never reads as "No gaps found".
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
- CR-16 leaves out, each with its own note:
  - a rule whose network security group is attached to no subnet or network interface. It exposes nothing today, so
    it is a cleanup item: delete the rule, or the group if it is unused, since attaching the group later would open
    the port.
  - a rule whose group is attached only to network interfaces of network virtual appliances (P0.6-APPLIANCES), where
    an untrust interface takes internet traffic by design. It is reviewed against the appliance's management design.
  - a rule whose group reaches an appliance through a subnet the appliance sits in, or through its network interface
    as well as other resources, since changing it would change the appliance too. It is reviewed with the client.
    NB.2-DETAIL lists every appliance network interface and its subnets, so an appliance interface without a group of
    its own is found through the group on its subnet.
  - a rule for a protocol other than TCP or any protocol, such as UDP 22 used by an application, which may not carry
    RDP, SSH or WinRM. It is reviewed with the client.
  - a rule whose destination ports include `*` or a range, which may not mean a management port is meant to be
    open. It is reviewed with the client and narrowed, and a later pack picks it up once it names a management port.

  When only those remain, CR-16 reads "Only rules for cleanup or review remain, see the notes".
- AKS node pools (a scale set in the node resource group of a cluster, or tagged `aks-managed-`) get no change
  request. AKS sets encryption at host only when a node pool is created, so an existing pool is replaced: a new node
  pool created with `--enable-encryption-at-host`, its workloads moved across and the old pool removed. That needs
  capacity, disruption budgets and the pool settings agreed with the client, so the index names each cluster and
  node pool and routes them to a planned project instead of a low-impact change.

## Licensing gate

A change request can depend on a license. The generator derives the licensing check from the pack's own reads
(LIC.1-SKUS, LIC.2-MACHINES, LIC.3-TVM, LIC.4-DEVICES and P0.3, collector 1.11.0) with `report/Get-CyberSocLicensing.ps1`,
the code the collector runs for LIC.5-MATRIX, so `-DefenderEndpointPlan` given here replaces the reading the collection
recorded. Each capability reads Licensed, Partly licensed, Not licensed or Unknown:

- A change request whose capability reads Not licensed is not written. Its index status reads "Not written, needs
  <capability>, which reads Not licensed", and its note gives the basis, such as no license in the tenant carrying the
  service plan.
- Unknown writes the change request, adds ", confirm the license before sending" to its status, and a note names the
  capability and why it could not be established. A read that failed, was refused or is partial, and a pack collected
  before 1.11.0, read Unknown, never Not licensed.
- Partly licensed writes the change request with a note saying what is not covered, such as the servers without a
  server license.

`00-index.md` has a Licensing section on every run: the Defender for Endpoint plan and where it comes from, the device
counts (onboarded clients and servers, the clients tagged `License MDE P1`, the servers without a server license, the
devices security settings management manages), and a table of every capability with its reading, seats, assigned
licenses, the change requests that need it and the basis. Without a recorded reading it asks for the Licenses page,
which has no API. On a pack collected before 1.11.0 the section says every capability reads Unknown and asks for a
recollection.

A change request registers the capability it needs in its catalog entry in `New-CyberSocChangeRequests.ps1`:
`Requires = @('<key>')` gates it as above, and `Uses = @('<key>')` lists it in the index without a gate, as CR-16 does
for Defender for Servers Plan 2, which just-in-time VM access needs while Azure Bastion does not. The keys are those of
`Get-CyberSocCapabilityCatalog` in `report/Get-CyberSocLicensing.ps1`:

| Key | Capability |
|---|---|
| `EntraIdP1` | Microsoft Entra ID P1, for Conditional Access |
| `EntraIdP2` | Microsoft Entra ID P2 |
| `MdePlan1Sku`, `MdePlan2Sku`, `MdeBusinessSku`, `MdeServerSku`, `MdeUserSku` | The Defender for Endpoint licenses: Plan 1, Plan 2, Defender for Business, Defender for Endpoint for servers, and any user license |
| `TvmPremium` | Defender Vulnerability Management premium |
| `MdoP1`, `MdoP2` | Defender for Office 365 Plan 1 (Plan 2 includes it) and Plan 2 |
| `Mdi`, `Mdca`, `DefenderXdr` | Defender for Identity, Defender for Cloud Apps, Microsoft Defender XDR |
| `IntuneP1` | Microsoft Intune Plan 1 |
| `DefenderServers`, `DefenderServersP2`, `DefenderContainers` | Defender for Servers (any plan, and Plan 2) and Defender for Containers, on every subscription in the pack (Partly licensed on some) |
| `MdeServers` | Defender for Endpoint on servers: a server license for each onboarded server |
| `MdeVulnerabilityData` | Defender for Endpoint Plan 2 or Defender for Servers, the vulnerability and configuration data behind EW.3, EW.4 and EW.5. Like `MdeServers`, it reads neither Licensed nor Not licensed from the API reads, which list only the devices the account's device groups allow, so a change request that requires either is always written, with a note to confirm or to say what is not covered |
| `MdeSecurityManagement` | Defender for Endpoint security settings management, which needs a Defender for Endpoint user license even where Defender for Servers covers the servers |

A new capability adds an entry to that catalog with its service plan IDs from Microsoft Learn (Product names and
service plan identifiers for licensing), or its Defender for Cloud plan from P0.3.

## Emergency access accounts

Every Conditional Access change excludes the emergency access accounts and never removes their access (decision 4 of
the October 21 review). They are every account with Atmosera in its UPN and every member of an Atmosera group, a
group whose display name contains Atmosera, read by the collector into IA.16-ACCOUNTS and IA.16-GROUPS (collector
1.12.0). `report/Get-CyberSocEmergencyAccess.ps1` holds the match and one helper that every Conditional Access change
calls, `Get-CyberSocEmergencyAccess`, which the generator runs once into `$emergencyAccess`:

| Field | What it holds |
|---|---|
| `Ready` | True only when both reads are complete (OK or EMPTY, readable) and found at least one account |
| `Why` | Why it is not ready: `Missing` on a pack collected before 1.12.0, the result that is not complete, or no account found |
| `ExcludeGroups` | The object ID of each Atmosera group. A policy excludes the group, so a new member is covered without a change |
| `ExcludeUsers` | The object ID of each account matched by its UPN, excluded on its own even when it also sits in an Atmosera group, so it stays excluded if it is taken out of the group |
| `Accounts`, `Groups` | The IA.16-ACCOUNTS and IA.16-GROUPS rows |
| `Review` | The Atmosera groups whose membership is dynamic or synced from on-premises |
| `Protected` | Every account and group ID above. `Test-CyberSocEmergencyAccessId $emergencyAccess <id>` is true for one, and a change that removes stale exclusions keeps it |

A change request marks itself a Conditional Access change with `EmergencyAccess = $true` in its catalog entry. It is
then written only when `$emergencyAccess.Ready`. Otherwise its status reads "Not written" with the reason, or "Needs
recollection with CyberSOC collector 1.12.0 or later", and a note says a Conditional Access change is written only with
the emergency access accounts it excludes. A read that failed, is partial, is unreadable or found no Atmosera account
never lets one through.

`00-index.md` has an Emergency access accounts section on every run: the rule, which change requests it gates, a
table of the Atmosera groups (members, membership type, object ID) and of the accounts (UPN, name, user type, enabled,
how it matched, its Atmosera groups and whether a policy excludes it through its group, on its own, or both), a note for each
dynamic or synced group, whose members can drop out of the exclusion, and the reminder that an account Atmosera uses
without the word in its UPN is covered only when it sits in an Atmosera group. When the read is not complete it says
why no Conditional Access change can be written.

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
- Every change request writes a client email (`CR-NN-<change>.email.txt`) that asks for the client's approval,
  built by the one shared builder, `New-ApprovalEmail`. The generator stops before writing anything when a change
  request has no approval request, and the Pester suite fails when any change request from CR-01 to CR-19 is written
  without one, or with an email that leaves the shared structure, carries a title, or opens two paragraphs the same
  way. A new change request builds its email the same way.

Every client email asks for the client's approval and never presents the change as decided. Each one reads as a
letter: it is written in the first person singular, in plain, complete sentences, explains any technical term once,
and has no titles or heading lines. Each part is a plain paragraph whose opening sentence says what the part is, in
its own words for that change, and no two paragraphs open with the same words. The parts always come in the same
order:

1. The subject, `Approval requested: <change>`.
2. The greeting, `Hello <-ClientContact>,` or `Hello,`.
3. The ask, in one or two sentences, opening "I would like your approval to ...".
4. Why, as a because sentence, for example "I recommend setting this minimum because TLS 1.0 and 1.1 have known
   weaknesses ...": the risk the change reduces.
5. What it means for the client: the expected effect and the reason for it, usually no visible effect because the
   platform already refuses what the setting turns off, or a restart that needs a maintenance window.
6. The resources, introduced in a sentence and listed by subscription. CR-19 also lists the management groups and
   the root scope above the subscriptions, each under a line of its own, and the Microsoft Entra roles under
   `Microsoft Entra ID directory roles:`, since they belong to no subscription. Its email counts the accounts and
   roles under each line rather than naming them, and names them in `CR-19-disabled-account-roles.email.csv`, written
   beside the email to attach, since the list can be long: one line per role with the account, its sign-in name, the
   role, where it applies, how the account holds it (assigned to it, or through a group, nested or not) and what the
   change does about it, including the memberships it leaves alone.
7. How the change can be reversed, or that it cannot.
8. The request: approval of the proposed date (`-ChangeDate`, two weeks after the build by default), or, for CR-09
   and CR-15, which restart each machine, approval of the change and a maintenance window. It asks for a reply by a
   week before the proposed date and always ends with "I will not schedule this change until I have your approval."
9. The sign-off, `Thank you,` and `-SenderName`.

`New-ApprovalEmail` turns the first sentence of the ask into "I would like your approval to ...", and stops the run
when the why is not an "I recommend ... because" sentence or two paragraphs open with the same three words.
`Assert-ApprovalEmail` in the Pester suite reads every generated email the same way: no old title line and no short
line standing alone as a heading, the parts in order by what each paragraph says, a because sentence for the why,
distinct openings, and the request with its reply-by date and closing promise.

Each change keeps its own content inside that structure:

- CR-01 and CR-10 send resource logs to the client's Sentinel workspace, so their emails say that this adds Log
  Analytics ingestion, billed by volume, and that the Activity log is ingested at no charge. CR-10 names the type of
  each resource.
- CR-06 lists the vaults with the soft delete retention period of each, says that purge protection cannot be undone,
  and that a deleted vault, key, secret or certificate is kept for that period, cannot be purged early and keeps its
  name until the period ends. It asks for the client's written approval. With `-PurgeProtectionApproved` it refers to
  the approval given at build kickoff instead, and asks the client to confirm it still stands and to approve the
  proposed date.
- CR-07 walks through why nothing breaks (every container is private, sign-in, shared access signature and account
  key access are unaffected, and a static website, whose `$web` container Azure serves anonymously whatever the
  setting, keeps working), says each account is checked again just before the change, and offers to turn the setting
  back on straight away.
- CR-08 asks whether anything still calls the apps over HTTP, and CR-13 whether anything still connects with TLS 1.0
  or 1.1, before asking for approval.
- CR-09 and CR-15 explain the restart of each machine or instance, and CR-15 the scale sets whose upgrade policy may
  restart instances on their own.
- CR-16 says that a new RDP, SSH or WinRM connection from the internet will be refused while an open one stays up,
  explains just-in-time VM access and Azure Bastion with their cost, says that Bastion provides RDP and SSH sessions
  only, so where a rule opens WinRM, remote PowerShell continues through just-in-time VM access or from named addresses, (Defender for Servers Plan 2, or Bastion by the
  hour, whose free Developer tier is for development and test only), states which subscriptions have Plan 2 (a
  subscription P0.3 did not read stays unknown, never off) and suggests the path that fits, and lists each rule with its group, priority, ports, source and where it applies. Before
  asking for approval it asks who still needs those ports from the internet and from which addresses, and which
  replacement the client wants, and, where a rule is open to every address, the address ranges of the virtual
  networks, peered networks and on-premises networks that connect, or that nothing connects from them. It offers to
  narrow a rule to named addresses instead of removing it. With `-AdminRuleOpen`, one more paragraph names each
  machine with its ports, says a central network policy, a security admin rule in Azure Virtual Network Manager, keeps
  them open to the internet ahead of any network security group rule, and asks who manages the Virtual Network
  Manager configuration.
- CR-17 says that plain FTP stops working, that Disabled turns FTPS off too, that deployment methods other than
  FTP are not affected, and, where an app is below TLS 1.2, that FTPS only needs the minimum TLS request first. It
  lists each app with its FTP state, and before asking for approval it asks whether any deployment tool or person
  still connects over FTP or FTPS, to upload files or to download files or logs, and whether FTPS only or Disabled
  suits each app. Disabled is set only where nothing uses FTP or FTPS at all.
- CR-18 lists the containers by subscription and account, one line per account with its containers counted and
  each container's level, and says that anyone can read every one of them today without signing in. It says that
  setting them to private stops anonymous reads straight away, so a website, application, content delivery network or
  link that reads them without signing in gets an error, while sign-in, shared access signature and account key access
  keep working and a static website is not affected. Before asking for approval it asks the owner of each container
  to confirm that it serves no public content, or to move its files to shared access signatures, on their own or
  through a content delivery network such as Azure Front Door that adds the signature, and says a container that still
  serves public content stays out until then. It offers to set each container back while its account still allows
  anonymous access.
- CR-19 counts the accounts and roles by subscription, management group, root scope and the Microsoft Entra roles,
  and names each account with its roles in plain words in the attached CSV. It says that nobody loses access today,
  since the accounts cannot sign in, that an account back in use later would need its roles assigned again and its
  group memberships restored, that where a group holds the role the account is removed from the group, the nested
  group where it sits in one, rather than the role taken from the group, so the other members keep their access, that
  removing an account from a group also ends anything else the group gives it, that a membership a rule or the
  on-premises directory decides stays as it is, marked in the file, and that each account is checked again just
  before the change. Where the file also lists a role that stays, the email speaks of the roles marked for removal
  rather than of every role in the file, and, where that role belongs to an account outside the change, of every
  disabled account in the file rather than of the accounts in the change. A value
  in the file that a spreadsheet would read as a formula, one starting with `=`, `+`, `-` or `@`, such as a display
  name from the directory, gets an apostrophe in front, which the spreadsheet hides. It offers to restore any role from the record and to add an account back to its group, and
  before asking for approval it asks whether any account is expected back in use, such as someone on leave or a
  seasonal worker, or is kept for emergency access, and says such an account stays out of the change.
- CR-05, CR-11, CR-12 and CR-14 say that the change cannot be reversed, because the service takes no lower minimum,
  and why no reversal should be needed.

The index lists which emails propose the date and which ask for a maintenance window, with the reply-by date.

Each claim in the emails was checked on Microsoft Learn: secure transfer rejects HTTP requests and SMB without
encryption (Require secure transfer to ensure secure connections), the TLS retirement dates and minimums of each
service (the pages each change request cites), the Log Analytics ingestion charge for resource logs sent through
diagnostic settings (Azure Monitor cost and usage), and the Activity log collected at no charge (Azure Monitor data
sources, Microsoft Sentinel free data sources). For CR-16: a security rule change applies only to new connections
and an open one stays up (Azure network security groups overview), just-in-time VM access needs Defender for Servers
Plan 2 on the subscription and an existing rule on the selected ports keeps priority over its deny rules (Enable
just-in-time access, Just-in-time machine access), Bastion provides RDP and SSH connectivity, connects over TLS on port 443, is billed hourly
from deployment and offers a Developer tier for development and test only (What is Azure Bastion, Bastion SKU
comparison, Deploy Azure Bastion from the Azure portal), the VirtualNetwork service tag includes the address prefixes
used on user-defined routes and might contain default routes (Azure service tags overview), and the effective security
rules of a network interface are under Networking, the network interface, then Help, Effective security rules, for a
running virtual machine (Create, change, or delete a network interface), the effective security rules include the
admin rules Azure Virtual Network Manager applies to the virtual network (Effective security rules overview, View
configurations applied by Azure Virtual Network Manager), and security admin rules are evaluated before network
security groups, with Always Allow and Deny ending the evaluation and Allow passing it on to the groups (Security
admin rules in Azure Virtual Network Manager). For CR-17: the FTP state is set under
Configuration, General settings, Platform settings, to FTPS only or to Disabled, which turns off FTP and FTPS, FTPS only
does not support TLS 1.0 or 1.1, and the FTP and FTPS endpoint is active on an app without any configuration (Deploy
your app to Azure App Service using FTP/S), the API takes `AllAllowed`, `FtpsOnly` and `Disabled` and documents no
default (Microsoft.Web sites/config), and FTP basic authentication is a separate setting (Disable basic authentication
in Azure App Service deployments). For CR-18: a container's level is set under Data storage, Containers, Change
access level, a container can be opened to Blob or Container only while the account allows anonymous access, and the
portal setting is disabled while it does not, and the account setting overrides the container level (Configure
anonymous read access for containers and blobs, Remediate anonymous read access to blob data), the `$web` container
level does not affect the static website endpoint (Static website hosting in Azure Storage), and Azure Front Door in
front of a private container authenticates with a shared access signature (Use Azure Front Door with Azure Storage
Blobs). For CR-19: an Azure role assignment is removed under Access control (IAM), Role assignments at the scope where
it was made, and an inherited one cannot be removed at a child scope (Remove Azure role assignments), an assignment at
the root scope is removed with Azure PowerShell, the Azure CLI or the REST API rather than the portal (Elevate access
to manage all Azure subscriptions and management groups), a Microsoft Entra role is removed under Roles and admins and
a role held through a group by removing the account from the group (Remove Microsoft Entra role assignments), a group
member is removed under Groups, All groups, the group, Members, Remove, and added back with Add, a security group can
be nested in another security group but a group cannot be a member of a role-assignable group (Manage Microsoft Entra
groups and group membership), an
eligible one in Privileged Identity Management, which does not remove the last Global Administrator assignment, and an
eligible assignment is recreated there with its start and end date and time, or as permanent (Assign Microsoft Entra
roles in Privileged Identity Management), an Azure role assignment's State column reads Active time-bound and Edit
columns shows its start and end time (List Azure role assignments using the Azure portal), and it is recreated as
Active and Time bound with that end on the Assignment type tab before Review + assign, or edited afterwards from its
State link (Assign Azure roles using the Azure portal), while a resource scope has neither, so a time-bound assignment
on a resource is read and recreated in Privileged Identity Management (Assign Azure resource roles in Privileged
Identity Management), and Resource Graph returns assignments at parent scopes only
with the `AtScopeAboveAndBelow` scope filter and holds role assignments, role definitions and classic administrators
only (Understanding the Azure Resource Graph query language, Azure Resource Graph table and resource type reference). A role assignment condition filters down what the role grants and is added under Conditions in the code editor, except at a management group scope, where the portal cannot add one (Azure role assignment conditions, Add or edit Azure role assignment conditions using the Azure portal, using Azure CLI), and an Entra role can be scoped to a single app registration, which is assigned from App registrations, the application, Roles and administrators (Assign Microsoft Entra roles).

Every change request, email and the index keep to the copy rules: no semicolons, arrows (Unicode arrows and `->`,
`<-`, `=>`), emoji or angle brackets, and the greater-than sign only in navigation steps such as Settings >
Configuration. A client email has no navigation steps, so it has no greater-than sign at all. The CSV is tracking data and carries
each resource ID exactly as Azure has it. Values read from the pack are cleaned of every character the check
rejects, and a file that still breaks a rule stops the run before any file is written.

## Output

| File | Contents |
|---|---|
| `CR-NN-<change>.txt` | One change request |
| `CR-NN-<change>.email.txt` | The client email for that change, subject line first |
| `00-index.md` | Every change with its status and files, the licensing check with the change requests that depend on each capability, and notes on the resources left out |
| `change-requests.csv` | One row per resource, and one per container for CR-18 (`account/container`): CR, Change, Subscription, ResourceGroup, Resource, CurrentSetting, ResourceId |

Each change reports one of these statuses in the index: change request and client email (with ", confirm the
license before sending" when a capability it needs reads Unknown), not written because a capability it needs reads Not
licensed, no gaps found, not collected with the manifest status, result file unreadable, or needs recollection with CyberSOC collector 1.1.0 or
later (1.2.0 or later for CR-11 to CR-14, 1.3.0 or later for CR-15, 1.4.0 or later for CR-09 and CR-15 when they
have a machine or scale set to change, 1.6.0 or later for CR-16, 1.7.0 or later for CR-17, and 1.8.0 or later for CR-18). A result the manifest reads as OK or PARTIAL whose file is missing, empty or not valid JSON is unreadable, never
read as no gaps. A change request that also reads a result beyond its sources (DR.6-COVERAGE and P0.5 for CR-01,
DR.6-NONCOMPLIANT for CR-10, DP.1-CONTAINERS for CR-07 and CR-18, DP.4-VMSS-ELIGIBILITY for CR-09 on a 1.3.0 pack, P0.3 for
CR-16) reads "partial
collection scope" when that result
is PARTIAL, and gets a note in the index when it was not collected or is unreadable.

Every file is built and checked against the copy rules before the folder is touched, so a run that stops leaves the
earlier files as they were. The per-resource
results (P0.7, NB.4-DETAIL, NB.5-DETAIL, NB.6-DETAIL, DP.1-DETAIL, DP.2-DETAIL, DP.4-ELIGIBILITY,
DR.6-COVERAGE, DR.6-NONCOMPLIANT) were added in collector 1.1.0, and NB.6-PAAS-DETAIL, which lists the Redis caches,
Service Bus and Event Hubs namespaces and Cosmos DB accounts below TLS 1.2 for CR-11 to CR-14, in 1.2.0.
DP.4-VMSS-ELIGIBILITY, which lists the scale sets without encryption at host for CR-15, and the ScaleSet column of
DP.4-ELIGIBILITY were added in 1.3.0, and the VmId column of DP.4-ELIGIBILITY and the UniqueId column of
DP.4-VMSS-ELIGIBILITY in 1.4.0. NB.2-DETAIL, which lists the internet-exposed management port rules for CR-16
with every property and attachment, was added in 1.6.0, and NB.5-FTPS-DETAIL, which lists the App Service apps
that still allow plain FTP for CR-17, in 1.7.0. DP.1-CONTAINERS-DETAIL, which lists each container set to Blob or
Container for CR-18, was added in 1.8.0 and is written by the DP.1-CONTAINERS engine. The ScmMinTlsVersion column of
NB.5-DETAIL, the SCM (Kudu) site minimum TLS version CR-04 sets, was added in 1.13.0. Their queries are in section 6 of the CyberSOC Monthly Report Runbook.

## Validation

```powershell
Invoke-Pester -Path tests/New-CyberSocChangeRequests.Tests.ps1
```

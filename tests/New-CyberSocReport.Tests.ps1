BeforeAll {
    $generator = Join-Path $PSScriptRoot '../New-CyberSocReport.ps1'
    # Windows PowerShell 5.1 writes the array ConvertFrom-Json parses to the pipeline as one object.
    # PowerShell 7 does the same with -NoEnumerate, so this runs a script block as 5.1 reads JSON.
    function Invoke-WithWindowsPowerShellJson([scriptblock]$Script) {
        function ConvertFrom-Json { param([Parameter(ValueFromPipeline, Position = 0)]$InputObject) process { Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject $InputObject -NoEnumerate } }
        & $Script
    }
    function New-ReportFixture {
        param([string]$Path)
        New-Item -ItemType Directory -Path (Join-Path $Path 'results') -Force | Out-Null
        @{ ClientName = 'Example Client'; TenantId = 'example-tenant'; WindowStart = '2026-07-01'; WindowEnd = '2026-09-30'; RecentStart = '2026-07-01'; PostureReadDate = '2026-10-08'; Subscriptions = @('sub-1'); Workspaces = @() } |
            ConvertTo-Json -Depth 6 | Set-Content (Join-Path $Path '00-parameters.json')
        @(
            [pscustomobject]@{ ResultId = 'OUT.5'; Status = 'OK'; Rows = 1; ReadTimeUtc = '2026-10-08T10:00:00Z' },
            [pscustomobject]@{ ResultId = 'NB.1'; Status = 'OK'; Rows = 3; ReadTimeUtc = '2026-10-08T10:00:00Z' },
            [pscustomobject]@{ ResultId = 'DP.5b'; Status = 'OK'; Rows = 2; ReadTimeUtc = '2026-10-08T10:00:00Z' },
            [pscustomobject]@{ ResultId = 'OUT.4'; Status = 'OK'; Rows = 1; ReadTimeUtc = '2026-10-08T10:00:00Z' }
        ) | Export-Csv (Join-Path $Path '00-manifest.csv') -NoTypeInformation
        '[{"Alerts":12,"ProductName":"Example","AccountUpn":"private@example.test","ClassificationComment":"Internal notes"}]' |
            Set-Content (Join-Path $Path 'results/OUT.5.json')
        '[{"Vnet":"v","SubnetName":"secret-subnet-a","SubnetClass":"Workload","Segmented":1},{"Vnet":"v","SubnetName":"secret-subnet-b","SubnetClass":"Workload","Segmented":0},{"Vnet":"v","SubnetName":"gw","SubnetClass":"Gateway","Segmented":0}]' |
            Set-Content (Join-Path $Path 'results/NB.1.json')
        '[{"VmName":"secret-vm-1","ProtectionState":""},{"VmName":"secret-vm-2","ProtectionState":""}]' |
            Set-Content (Join-Path $Path 'results/DP.5b.json')
        '[{"IncidentNumber":5,"Title":"Secret incident title","Severity":"High","ClassificationComment":"Private comment","ExfilOrImpactTactic":false}]' |
            Set-Content (Join-Path $Path 'results/OUT.4.json')
    }
}
Describe 'Offline HTML report generation' {
    BeforeEach {
        $pack = Join-Path $TestDrive ([guid]::NewGuid().ToString())
        New-ReportFixture $pack
    }
    It 'embeds the selected aggregate evidence and assets without changing the evidence' {
        $before = (Get-FileHash (Join-Path $pack 'results/OUT.5.json')).Hash
        $file = (& $generator -SkipDeck -EvidencePath $pack -Depth Detailed)[0]
        $html = Get-Content $file -Raw
        $html | Should -Match 'data:image/jpeg;base64,'
        $html | Should -Match '"depth":"detailed"'
        $html | Should -Match '"Alerts":12'
        $html | Should -Match '"RecentStart":"2026-07-01"'
        $html | Should -Not -Match 'private@example.test|Internal notes|<script src=|<link[^>]*href='
        (Get-FileHash (Join-Path $pack 'results/OUT.5.json')).Hash | Should -Be $before
    }
    It 'embeds the federation provider and MFA behavior but never the federated domains or their URIs' {
        $m = @(Import-Csv (Join-Path $pack '00-manifest.csv'))
        $m += [pscustomobject]@{ ResultId = 'IA.1-FEDERATION'; Status = 'OK'; Rows = 2; ReadTimeUtc = '2026-10-08T10:00:00Z' }
        $m += [pscustomobject]@{ ResultId = 'IA.1'; Status = 'OK'; Rows = 1; ReadTimeUtc = '2026-10-08T10:00:00Z' }
        $m | Export-Csv (Join-Path $pack '00-manifest.csv') -NoTypeInformation
        '[{"Domain":"secret-domain.test","IsRoot":true,"IdentityProvider":"Okta","IssuerUri":"secret-domain.test:exk123","PassiveSignInUri":"https://sso.secret-domain.test/app/office365/exk123/sso/wsfed/passive","ActiveSignInUri":"https://sso.secret-domain.test/x","PreferredAuthenticationProtocol":"wsFed","FederatedIdpMfaBehavior":"enforceMfaByFederatedIdp","ConfigSource":"Read"},{"Domain":"eu.secret-domain.test","IsRoot":false,"IdentityProvider":"","IssuerUri":"","PassiveSignInUri":"","ActiveSignInUri":"","PreferredAuthenticationProtocol":"","FederatedIdpMfaBehavior":"","ConfigSource":"Inherited from secret-domain.test"}]' |
            Set-Content (Join-Path $pack 'results/IA.1-FEDERATION.json')
        '[{"UserType":"Member","UsersSignedIn":1414,"UsersChallenged":563,"UsersAlwaysMfa":1,"UsersExternalMfa":563,"UsersEntraMfa":60,"PctChallenged":39.8,"PctAlwaysMfa":0.1,"MfaAtLeastOnce":563,"MfaEveryAppSignIn":1,"CoveredEveryAppSignIn":5,"FederatedMfaAtLeastOnce":563,"FederatedWithoutMfa":2,"NoMfaOnlyUnevaluated":550,"MfaSessionLinkedOnly":31}]' |
            Set-Content (Join-Path $pack 'results/IA.1.json')
        $html = Get-Content (& $generator -SkipDeck -EvidencePath $pack)[0] -Raw
        $html | Should -Match '"IA.1-FEDERATION":\[\{"FederatedDomains":2,"ConfigsRead":1,"Provider":"Okta","MfaBehavior":"enforceMfaByFederatedIdp","MfaBehaviorUnset":0\}\]'
        $html | Should -Match '"NoMfaOnlyUnevaluated":550,"MfaSessionLinkedOnly":31'
        $html | Should -Not -Match 'secret-domain|exk123|wsfed'
    }
    It 'embeds the IA.5 phone-only count with the registration counts and never a user identifier' {
        $m = @(Import-Csv (Join-Path $pack '00-manifest.csv'))
        $m += [pscustomobject]@{ ResultId = 'IA.5'; Status = 'OK'; Rows = 1; ReadTimeUtc = '2026-10-08T10:00:00Z' }
        $m | Export-Csv (Join-Path $pack '00-manifest.csv') -NoTypeInformation
        '[{"Members":200,"MfaRegistered":180,"MfaCapable":178,"SsprRegistered":150,"PasswordlessCapable":30,"PhishingResistant":25,"PhoneRegistered":90,"AuthenticatorRegistered":150,"PhoneOnly":12,"Admins":5,"AdminsMfaRegistered":5,"UserPrincipalName":"private@example.test","Id":"0f0e0d0c-aaaa-bbbb-cccc-000000000001"}]' |
            Set-Content (Join-Path $pack 'results/IA.5.json')
        $html = Get-Content (& $generator -SkipDeck -EvidencePath $pack)[0] -Raw
        $html | Should -Match '"AuthenticatorRegistered":150,"PhoneOnly":12,"Admins":5'
        $html | Should -Not -Match 'private@example.test|0f0e0d0c-aaaa'
    }
    It 'reduces resource-level results to counts and keeps names, titles and comments out of the report' {
        $html = Get-Content (& $generator -SkipDeck -EvidencePath $pack)[0] -Raw
        $html | Should -Match '"WorkloadSubnets":2'
        $html | Should -Match '"Segmented":1'
        $html | Should -Match '"VmsWithoutBackup":2'
        $html | Should -Not -Match 'ExfilOrImpactTactic' -Because 'the CyberSOC report carries no data loss flag, even from a pack collected with one'
        $html | Should -Not -Match 'secret-subnet|secret-vm|Secret incident title|Private comment|"Title"'
    }
    It 'reduces attack disruption results (OUT.7) to a count and never embeds their incident numbers or titles' {
        '[{"IncidentNumber":9900417,"Title":"Secret disruption title","Severity":"High","CreatedTime":"2026-08-01T00:00:00Z","Classification":"TruePositive"},{"IncidentNumber":9900418,"Title":"Secret disruption title","Severity":"Medium","CreatedTime":"2026-08-02T00:00:00Z","Classification":"TruePositive"}]' |
            Set-Content (Join-Path $pack 'results/OUT.7.json')
        $html = Get-Content (& $generator -SkipDeck -EvidencePath $pack)[0] -Raw
        $html | Should -Match '"OUT.7":\[\{"Incidents":2\}\]'
        $html | Should -Not -Match '9900417|9900418|Secret disruption title|IncidentNumber'
    }
    It 'embeds true positive detection titles only after screening, with the tactics and the day, and never the comments' {
        $p = Get-Content (Join-Path $pack '00-parameters.json') -Raw | ConvertFrom-Json
        $p | Add-Member -NotePropertyName TicketPattern -NotePropertyValue '(?i)\bSR\s*\d{3,}'
        $p | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $pack '00-parameters.json')
        @'
[{"IncidentNumber":110,"Title":"Password spray attack against Microsoft Entra ID application","Severity":"Medium","CreatedTime":"2026-07-28T04:15:35.186Z","ClassificationReason":"SuspiciousActivity","ClassificationComment":"Reviewed activity from IP 2001:db8::1 against pat.doe@contoso.test (per ZD ticket 9900001).","Tactics":"[\"CredentialAccess\"]","ExfilOrImpactTactic":false},
 {"IncidentNumber":111,"Title":"Suspicious inbox rule for jane.doe@example.test","Severity":"High","CreatedTime":"2026-08-01T00:00:00Z","ClassificationComment":"x","Tactics":"[\"Collection\"]","ExfilOrImpactTactic":true},
 {"IncidentNumber":112,"Title":"Sign-in from 203.0.113.53","Severity":"High","CreatedTime":"2026-08-02T00:00:00Z","Tactics":"[\"InitialAccess\"]","ExfilOrImpactTactic":false},
 {"IncidentNumber":113,"Title":"Malware on DESKTOP-4F2KQ1","Severity":"High","CreatedTime":"2026-08-03T00:00:00Z","Tactics":"[\"Execution\"]","ExfilOrImpactTactic":false},
 {"IncidentNumber":114,"Title":"Beacon to c2.badsite.example","Severity":"High","CreatedTime":"2026-08-04T00:00:00Z","Tactics":"[\"CommandAndControl\"]","ExfilOrImpactTactic":false},
 {"IncidentNumber":115,"Title":"Script run from \\\\fs01\\share","Severity":"Low","CreatedTime":"2026-08-05T00:00:00Z","Tactics":"[\"Execution\"]","ExfilOrImpactTactic":false},
 {"IncidentNumber":116,"Title":"Malware Scanning will stop soon: 75% of monthly gigabytes scan cap reached","Severity":"Low","CreatedTime":"2026-09-15T13:01:36Z","Tactics":"[]","ExfilOrImpactTactic":false},
 {"IncidentNumber":117,"Title":"Multi-stage incident involving Initial access and Execution on one endpoint","Severity":"High","CreatedTime":"2026-08-01T00:30:00","Tactics":"[\"InitialAccess\",\"Execution\"]","ExfilOrImpactTactic":false},
 {"IncidentNumber":118,"Title":"Suspicious behavior by cmd.exe was observed","Severity":"Medium","CreatedTime":"2026-08-06T23:30:00","Tactics":"[\"Execution\"]","ExfilOrImpactTactic":false},
 {"IncidentNumber":119,"Title":"Suspicious sign-in to application 3f2b8c1e-9d4a-4b7e-8c21-5a6f0d9e7b13","Severity":"Medium","CreatedTime":"2026-08-07T00:00:00Z","Tactics":"[\"InitialAccess\"]","ExfilOrImpactTactic":false},
 {"IncidentNumber":120,"Title":"Malware on desktop-4f2kq1","Severity":"High","CreatedTime":"2026-08-08T00:00:00Z","Tactics":"[\"Execution\"]","ExfilOrImpactTactic":false},
 {"IncidentNumber":121,"Title":"Sensitive file Q3_Payroll_Smith.xlsx shared externally","Severity":"High","CreatedTime":"2026-08-09T00:00:00Z","Tactics":"[\"Exfiltration\"]","ExfilOrImpactTactic":true},
 {"IncidentNumber":122,"Title":"Sign-in from 2001::1","Severity":"Medium","CreatedTime":"2026-08-10T00:00:00Z","Tactics":"[\"InitialAccess\"]","ExfilOrImpactTactic":false},
 {"IncidentNumber":123,"Title":"Escalated from ticket 9900001","Severity":"Medium","CreatedTime":"2026-08-11T00:00:00Z","Tactics":"[\"Persistence\"]","ExfilOrImpactTactic":false},
 {"IncidentNumber":124,"Title":"Escalated per ZD 12345","Severity":"Medium","CreatedTime":"2026-08-12T00:00:00Z","Tactics":"[\"Persistence\"]","ExfilOrImpactTactic":false},
 {"IncidentNumber":125,"Title":"Follow-up ZD#4521","Severity":"Medium","CreatedTime":"2026-08-13T00:00:00Z","Tactics":"[\"Persistence\"]","ExfilOrImpactTactic":false},
 {"IncidentNumber":126,"Title":"Script run from C:/Users/x","Severity":"Low","CreatedTime":"2026-08-14T00:00:00Z","Tactics":"[\"Execution\"]","ExfilOrImpactTactic":false},
 {"IncidentNumber":127,"Title":"__LONG__","Severity":"Low","CreatedTime":"2026-08-15T00:00:00Z","Tactics":"[\"Discovery\"]","ExfilOrImpactTactic":false},
 {"IncidentNumber":128,"Title":"Escalated as SR 4521","Severity":"Low","CreatedTime":"2026-08-16T00:00:00Z","Tactics":"[\"Discovery\"]","ExfilOrImpactTactic":false},
 {"IncidentNumber":129,"Title":"Malware detected on FILESERVER01","Severity":"High","CreatedTime":"2026-08-17T00:00:00Z","Tactics":"[\"Execution\"]","ExfilOrImpactTactic":false}]
'@.Replace('__LONG__', ('Repeated suspicious activity ' * 8).Trim()) | Set-Content (Join-Path $pack 'results/OUT.4.json')
        $html = Get-Content (& $generator -SkipDeck -EvidencePath $pack)[0] -Raw
        $html | Should -Match '"Threat":"Password spray attack against Microsoft Entra ID application","Tactics":"CredentialAccess","Created":"2026-07-28"'
        $html | Should -Match '"Threat":"Multi-stage incident involving Initial access and Execution on one endpoint","Tactics":"InitialAccess,Execution","Created":"2026-08-01"' -Because 'a time with no offset is read as UTC'
        $html | Should -Match '"Threat":"Suspicious behavior by cmd.exe was observed","Tactics":"Execution","Created":"2026-08-06"' -Because 'a program name is not a host name'
        ([regex]::Matches($html, '"Threat":"Title withheld"')).Count | Should -Be 16
        $html | Should -Match '"Threat":"","Tactics":"","Created":"2026-09-15"' -Because 'a true positive with no attack stage carries no title'
        $html | Should -Match '"Threat":"Title withheld","Tactics":"Discovery","Created":"2026-08-16"' -Because "the pack's own ticket pattern is applied"
        $html | Should -Match '"Threat":"Title withheld","Tactics":"Execution","Created":"2026-08-17"' -Because 'an all-caps machine name with a digit is withheld'
        $html | Should -Not -Match 'jane\.doe|203\.0\.113|2001:db8|2001::1|DESKTOP-4F2KQ1|FILESERVER01|badsite|fs01|3f2b8c1e|Payroll|ZD 12345|ZD#4521|C:/Users|Repeated suspicious|SR 4521|Malware Scanning|pat\.doe|contoso|9900001|ClassificationComment|IncidentNumber|"Title"'
        $html | Should -Not -Match 'An OUT\.4 row could not be screened, so its title was withheld'
    }
    It "withholds every true positive detection title and notes it once when the pack's ticket pattern is not a .NET regular expression" {
        $p = Get-Content (Join-Path $pack '00-parameters.json') -Raw | ConvertFrom-Json
        $p | Add-Member -NotePropertyName TicketPattern -NotePropertyValue '(?P<ref>SR\d+)'
        $p | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $pack '00-parameters.json')
        '[{"IncidentNumber":130,"Title":"Password spray attack against Microsoft Entra ID application","Severity":"Medium","CreatedTime":"2026-07-28T04:15:35Z","Tactics":"[\"CredentialAccess\"]","ExfilOrImpactTactic":false},{"IncidentNumber":131,"Title":"Suspicious inbox manipulation rule","Severity":"High","CreatedTime":"2026-07-29T00:00:00Z","Tactics":"[\"Collection\"]","ExfilOrImpactTactic":true}]' |
            Set-Content (Join-Path $pack 'results/OUT.4.json')
        $html = Get-Content (& $generator -SkipDeck -EvidencePath $pack)[0] -Raw
        $html | Should -Match '"Severity":"Medium","Threat":"Title withheld","Tactics":"","Created":""'
        $html | Should -Match '"Severity":"High","Threat":"Title withheld","Tactics":"","Created":""' -Because 'the severity survives a row that could not be screened'
        $html | Should -Not -Match 'ExfilOrImpactTactic'
        ([regex]::Matches($html, 'An OUT\.4 row could not be screened, so its title was withheld')).Count | Should -Be 1 -Because 'the review note is added once per report, not once per row'
        # The embedded data, not the report code: the CyberSOC model names Entra ID Protection detection types such as
        # Suspicious inbox manipulation rules.
        $data = [regex]::Match($html, '<script id="report-data" type="application/json">(.*?)</script>', 'Singleline').Groups[1].Value
        $data | Should -Not -BeNullOrEmpty
        $data | Should -Not -Match 'Entra ID application|inbox manipulation|Unrecognized grouping'
        $html | Should -Not -Match 'Entra ID application|Unrecognized grouping'
    }
    It "screens titles with the collector's default ticket pattern, character for character" {
        $literal = "(?m)^\`$script:EbrTicketPattern\s*=\s*'([^']+)'"
        $collector = [regex]::Match((Get-Content (Join-Path $PSScriptRoot '../Get-CyberSocEvidence.ps1') -Raw), $literal).Groups[1].Value
        $report = [regex]::Match((Get-Content $generator -Raw), $literal).Groups[1].Value
        $collector | Should -Not -BeNullOrEmpty
        $report | Should -BeExactly $collector
    }
    It 'evaluates Conditional Access from the raw policies and sign-in detail and embeds counts only' {
        $m = @(Import-Csv (Join-Path $pack '00-manifest.csv'))
        $m += [pscustomobject]@{ ResultId = 'IA.8-POLICIES'; Status = 'OK'; Rows = 1; ReadTimeUtc = '2026-10-08T10:00:00Z' }
        $m += [pscustomobject]@{ ResultId = 'IA.8-SIGNINS'; Status = 'OK'; Rows = 2; ReadTimeUtc = '2026-10-08T10:00:00Z' }
        $m += [pscustomobject]@{ ResultId = 'P0.6-APPLIANCES'; Status = 'OK'; Rows = 1; ReadTimeUtc = '2026-10-08T10:00:00Z' }
        $m | Export-Csv (Join-Path $pack '00-manifest.csv') -NoTypeInformation
        '[{"id":"P1","displayName":"Secret policy name","state":"enabled","conditions":{"users":{"includeUsers":["All"],"excludeUsers":["u1"]},"applications":{"includeApplications":["All"]},"clientAppTypes":["all"],"authenticationFlows":{"transferMethods":"deviceCodeFlow"}},"grantControls":{"builtInControls":["block"]}}]' |
            Set-Content (Join-Path $pack 'results/IA.8-POLICIES.json')
        '[{"Flow":"Device code","UserId":"u1","UserPrincipalName":"secret-room@example.test","PolicyResults":"p1=notApplied","SignIns":4},{"Flow":"Device code","UserId":"u2","UserPrincipalName":"secret-user@example.test","PolicyResults":"","SignIns":1}]' |
            Set-Content (Join-Path $pack 'results/IA.8-SIGNINS.json')
        '[{"Name":"secret-fw","Publisher":"paloaltonetworks","ResourceId":"/subscriptions/s/x/secret-fw"}]' | Set-Content (Join-Path $pack 'results/P0.6-APPLIANCES.json')
        $files = @(& $generator -SkipDeck -EvidencePath $pack)
        $html = Get-Content $files[0] -Raw
        $html | Should -Match '"Flow":"Device code","Control":"IA.3-DEVICECODE","PolicyRead":true,"PolicySource":"Raw","PolicyState":"Enforced","EnforcedPolicies":1,"ExcludedIdentities":1,"DetailRead":true,"SignIns":5,"SucceededExcluded":4,"AccountsExcluded":1,"SucceededUngoverned":1,"AccountsUngoverned":1'
        # Issue #27: the evaluator's counts reach the rendered client page as a count of accounts with excluded sign-ins beside In force,
        # with the review sentence and without approved wording. MFA at sign-in carries no per-account detail.
        $html | Should -Match '"Flow":"MFA at sign-in","Control":"IA.1","PolicyRead":true,"PolicySource":"Raw","PolicyState":"None","EnforcedPolicies":0,"ExcludedIdentities":0,"DetailRead":false'
        $client = Get-Content $files[1] -Raw
        $client | Should -Match '<h4>Device code flow sign-ins blocked</h4><p>[^<]*4 successful sign-ins by 1 account fell under exclusions in the policy, which can name users, groups, roles or applications\. Atmosera reviews these exclusions with your team at each business review\.'
        $client | Should -Match '<strong>In force</strong><span></span><span class="exceptions">1 account with excluded sign-ins</span>'
        $client | Should -Not -Match 'approved exception'
        $html | Should -Match '"Flow":"Legacy authentication","Control":"IA.3","PolicyRead":true,"PolicySource":"Raw","PolicyState":"None"'
        $html | Should -Match '"Appliances":1'
        $html | Should -Not -Match 'secret-room|secret-user|Secret policy name|secret-fw|"UserId"'
    }
    It 'grades location-based access from the raw policies and reads Unknown from the flattened inventory' {
        $m = @(Import-Csv (Join-Path $pack '00-manifest.csv'))
        $m += [pscustomobject]@{ ResultId = 'IA.8-POLICIES'; Status = 'OK'; Rows = 2; ReadTimeUtc = '2026-10-08T10:00:00Z' }
        $m | Export-Csv (Join-Path $pack '00-manifest.csv') -NoTypeInformation
        '[{"id":"L1","displayName":"Secret country block","state":"enabled","conditions":{"users":{"includeUsers":["All"],"excludeUsers":["u1","u2"]},"applications":{"includeApplications":["All"]},"clientAppTypes":["all"],"locations":{"includeLocations":["All"],"excludeLocations":["loc-us"]}},"grantControls":{"builtInControls":["block"]}},{"id":"L2","displayName":"MFA outside office","state":"enabled","conditions":{"users":{"includeUsers":["g1"]},"applications":{"includeApplications":["All"]},"clientAppTypes":["all"],"locations":{"includeLocations":["All"],"excludeLocations":["AllTrusted"]}},"grantControls":{"builtInControls":["mfa"]}}]' |
            Set-Content (Join-Path $pack 'results/IA.8-POLICIES.json')
        $html = Get-Content (& $generator -SkipDeck -EvidencePath $pack)[0] -Raw
        $html | Should -Match '"Flow":"Location","Control":"IA.4-LOCATION","PolicyRead":true,"PolicySource":"Raw","PolicyState":"Enforced","EnforcedPolicies":1,"ExcludedIdentities":2'
        $html | Should -Not -Match 'Secret country block|loc-us'
        $html | Should -Not -Match '"ConditionalAccessStatus"' -Because 'IA.4 no longer feeds the report'
    }
    It 'reduces blob container results to counts' {
        $m = @(Import-Csv (Join-Path $pack '00-manifest.csv'))
        $m += [pscustomobject]@{ ResultId = 'DP.1-CONTAINERS'; Status = 'PARTIAL'; Rows = 3; ReadTimeUtc = '2026-10-08T10:00:00Z' }
        $m | Export-Csv (Join-Path $pack '00-manifest.csv') -NoTypeInformation
        '[{"Account":"secretstore1","AccountAnonymousAccess":"Allowed","Containers":10,"PublicContainers":2,"ExposedContainers":2,"PublicContainerNames":"secret-cont (Blob)","ReadStatus":"OK"},{"Account":"secretstore2","AccountAnonymousAccess":"Disabled","Containers":5,"PublicContainers":1,"ExposedContainers":0,"PublicContainerNames":"old (Container)","ReadStatus":"OK"},{"Account":"secretstore3","Containers":0,"PublicContainers":0,"ExposedContainers":0,"ReadStatus":"HTTP 403"}]' |
            Set-Content (Join-Path $pack 'results/DP.1-CONTAINERS.json')
        $html = Get-Content (& $generator -SkipDeck -EvidencePath $pack)[0] -Raw
        $html | Should -Match '"DP.1-CONTAINERS":\[\{"Accounts":3,"AccountsUnread":1,"Containers":15,"PrivateContainers":12,"ExposedContainers":2,"AccountsExposed":1\}\]'
        $html | Should -Not -Match 'secretstore|secret-cont'
    }
    It 'falls back to the flattened policy inventory for packs before collector 1.10.0' {
        $m = @(Import-Csv (Join-Path $pack '00-manifest.csv'))
        $m += [pscustomobject]@{ ResultId = 'IA.8'; Status = 'OK'; Rows = 2; ReadTimeUtc = '2026-10-08T10:00:00Z' }
        $m | Export-Csv (Join-Path $pack '00-manifest.csv') -NoTypeInformation
        '[{"Policy":"Block Device Code Flow Enforcement","State":"enabled","IncludeUsers":"All","ExcludeUsers":"12 users","IncludeApplications":"All","ClientAppTypes":"all","AuthenticationFlows":"deviceCodeFlow","Grants":"block","Platforms":"","SignInRiskLevels":"","UserRiskLevels":"","AuthStrength":""},{"Policy":"Block legacy authentication","State":"enabled","IncludeUsers":"All","ExcludeUsers":"1 user, 1 role","IncludeApplications":"All","ClientAppTypes":"exchangeActiveSync,other","AuthenticationFlows":"","Grants":"block","Platforms":"","SignInRiskLevels":"","UserRiskLevels":"","AuthStrength":""}]' |
            Set-Content (Join-Path $pack 'results/IA.8.json')
        $html = Get-Content (& $generator -SkipDeck -EvidencePath $pack)[0] -Raw
        $html | Should -Match '"Flow":"Device code","Control":"IA.3-DEVICECODE","PolicyRead":true,"PolicySource":"Flattened","PolicyState":"Enforced","EnforcedPolicies":1,"ExcludedIdentities":12,"DetailRead":false'
        $html | Should -Match '"Flow":"Legacy authentication","Control":"IA.3","PolicyRead":true,"PolicySource":"Flattened","PolicyState":"Enforced","EnforcedPolicies":1,"ExcludedIdentities":2'
        $html | Should -Match '"Flow":"Admin portals","Control":"IA.1-ADMINPORTAL","PolicyRead":true,"PolicySource":"Flattened","PolicyState":"None"'
        $html | Should -Match '"Flow":"Location","Control":"IA.4-LOCATION","PolicyRead":true,"PolicySource":"Flattened","PolicyState":"Unknown"'
    }
    It 'reads legacy authentication and admin MFA as Unknown when no policy is enabled and security defaults were not read' {
        $m = @(Import-Csv (Join-Path $pack '00-manifest.csv'))
        $m += [pscustomobject]@{ ResultId = 'IA.8'; Status = 'OK'; Rows = 1; ReadTimeUtc = '2026-10-08T10:00:00Z' }
        $m | Export-Csv (Join-Path $pack '00-manifest.csv') -NoTypeInformation
        '[{"Policy":"Old pilot","State":"disabled","IncludeUsers":"All","IncludeApplications":"All","ClientAppTypes":"exchangeActiveSync,other","Grants":"block"}]' | Set-Content (Join-Path $pack 'results/IA.8.json')
        $html = Get-Content (& $generator -SkipDeck -EvidencePath $pack)[0] -Raw
        $html | Should -Match '"Flow":"Legacy authentication","Control":"IA.3","PolicyRead":true,"PolicySource":"Flattened","PolicyState":"Unknown"'
        $html | Should -Match '"Flow":"Admin portals","Control":"IA.1-ADMINPORTAL","PolicyRead":true,"PolicySource":"Flattened","PolicyState":"Unknown"'
        $html | Should -Match '"Flow":"Device code","Control":"IA.3-DEVICECODE","PolicyRead":true,"PolicySource":"Flattened","PolicyState":"None"' -Because 'security defaults do not block device code flow'
    }
    It 'escapes script terminators in client-controlled strings' {
        $p = Get-Content (Join-Path $pack '00-parameters.json') -Raw | ConvertFrom-Json
        $p.ClientName = '</script><script>alert(1)</script>'
        $p | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $pack '00-parameters.json')
        $files = @(& $generator -SkipDeck -EvidencePath $pack)
        foreach ($file in $files) { Get-Content $file -Raw | Should -Not -Match '<script>alert\(1\)</script>' -Because $file }
        Get-Content $files[0] -Raw | Should -Match '\\u003c/script\\u003e' -Because 'the internal edition escapes its embedded data'
    }
    It 'continues with a review item when a selected result file is malformed' {
        '{invalid' | Set-Content (Join-Path $pack 'results/OUT.5.json')
        $file = (& $generator -SkipDeck -EvidencePath $pack)[0]
        Get-Content $file -Raw | Should -Match 'OUT.5 could not be read'
    }
    It 'accepts the documented context fields and nothing else' {
        $ctx = Join-Path $TestDrive 'context.json'
        '{"ClientName":"Example Client","TenantId":"example-tenant","ServiceStartDate":"2024-01-15","TenantScore":{"Current":45,"Max":100,"ReadDate":"2026-10-08","Source":"Portal"},"Delivered":[],"Actions":[{"Key":"critical","Status":"Scheduled","Owner":"Client infrastructure team","TargetDate":"2026-11-30","Reference":"CHG-400","Reviewed":"2026-10-10","WindowStart":"2026-07-01","WindowEnd":"2026-09-30"}],"Impact":{"Confirmed":0,"Reviewed":"2026-10-10","Reference":"CHG-123","WindowStart":"2026-07-01","WindowEnd":"2026-09-30"},"OpenAlertNote":{"AwaitingClient":2,"InProgress":1,"Reviewed":"2026-10-10","Reference":"ZD 9900200","WindowStart":"2026-07-01","WindowEnd":"2026-09-30"},"ResponseTargetMinutes":60,"Raised":999}' | Set-Content $ctx
        $html = Get-Content (& $generator -SkipDeck -EvidencePath $pack -ContextPath $ctx)[0] -Raw
        $html | Should -Match '"ServiceStartDate":"2024-01-15"'
        $html | Should -Not -Match '"Impact":\{|CHG-123' -Because 'the CyberSOC report takes no impact determination, so an Impact record copied from an EBR context file is dropped'
        $html | Should -Match '"OpenAlertNote":\{"AwaitingClient":2,"InProgress":1,"Reviewed":"2026-10-10","Reference":"ZD 9900200","WindowStart":"2026-07-01","WindowEnd":"2026-09-30"\}'
        $html | Should -Match '"ResponseTargetMinutes":60'
        $html | Should -Match '"Actions":\[\{"Key":"critical","Status":"Scheduled","Owner":"Client infrastructure team","TargetDate":"2026-11-30","Reference":"CHG-400","Reviewed":"2026-10-10","WindowStart":"2026-07-01","WindowEnd":"2026-09-30"\}\]'
        $html | Should -Not -Match '"Raised":999'
    }
    It 'embeds the median time to triage from OUT.2 and OUT.2-ANALYST beside the close times' {
        $m = @(Import-Csv (Join-Path $pack '00-manifest.csv'))
        $m += [pscustomobject]@{ ResultId = 'OUT.2'; Status = 'OK'; Rows = 1; ReadTimeUtc = '2026-10-08T10:00:00Z' }
        $m += [pscustomobject]@{ ResultId = 'OUT.2-ANALYST'; Status = 'OK'; Rows = 1; ReadTimeUtc = '2026-10-08T10:00:00Z' }
        $m | Export-Csv (Join-Path $pack '00-manifest.csv') -NoTypeInformation
        '[{"Scope":"High","Incidents":30,"AutoClosed":4,"MedianTriageMin":6,"MedianCloseMin":7,"P90CloseMin":95}]' | Set-Content (Join-Path $pack 'results/OUT.2.json')
        '[{"Scope":"High","Incidents":26,"AutoClosed":0,"MedianTriageMin":9,"MedianCloseMin":40,"P90CloseMin":120}]' | Set-Content (Join-Path $pack 'results/OUT.2-ANALYST.json')
        $html = Get-Content (& $generator -SkipDeck -EvidencePath $pack)[0] -Raw
        $html | Should -Match '"OUT.2":\[\{"Scope":"High","Incidents":30,"AutoClosed":4,"MedianTriageMin":6,"MedianCloseMin":7,"P90CloseMin":95\}\]'
        $html | Should -Match '"OUT.2-ANALYST":\[\{"Scope":"High","Incidents":26,"AutoClosed":0,"MedianTriageMin":9,"MedianCloseMin":40,"P90CloseMin":120\}\]'
    }
    It 'rejects context from a different client' {
        $ctx = Join-Path $TestDrive 'wrong-client.json'
        '{"ClientName":"Someone else","TenantId":"example-tenant"}' | Set-Content $ctx
        { & $generator -SkipDeck -EvidencePath $pack -ContextPath $ctx } | Should -Throw '*must match*'
    }
    It 'rejects an unfinished pack rather than emitting a misleading report' {
        Remove-Item (Join-Path $pack '00-manifest.csv')
        { & $generator -SkipDeck -EvidencePath $pack } | Should -Throw '*missing 00-manifest.csv*'
    }
    It 'writes the PowerPoint edition beside the HTML from the same aggregates, with no names in it' -Skip:(-not (Get-Command node -ErrorAction SilentlyContinue)) {
        $files = @(& $generator -EvidencePath $pack -Depth Detailed)
        $files.Count | Should -Be 3
        $files[0] | Should -Match '03-security-report\.html$'
        $files[1] | Should -Match '03-security-report\.client\.html$'
        $files[2] | Should -Match '03-security-report\.pptx$'
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $zip = [IO.Compression.ZipFile]::OpenRead($files[2])
        try {
            $parts = @($zip.Entries | Where-Object { $_.FullName -match '^ppt/(slides/slide|notesSlides/notesSlide)\d+\.xml$' })
            @($parts | Where-Object { $_.FullName -match 'slides/slide' }).Count | Should -BeGreaterThan 10
            $text = ($parts | ForEach-Object { $r = [IO.StreamReader]::new($_.Open()); try { $r.ReadToEnd() } finally { $r.Dispose() } }) -join ' '
        }
        finally { $zip.Dispose() }
        $text | Should -Not -Match 'private@example.test|Internal notes|secret-subnet|secret-vm|Secret incident title|Private comment|object Object'
    }
    # The CyberSOC report says "True positive detections" where the EBR toolkit says "Confirmed threats" (issue #19).
    It 'labels the true positives True positive detections in every edition and never Confirmed threats' -Skip:(-not (Get-Command node -ErrorAction SilentlyContinue)) {
        $offline = Join-Path $TestDrive 'offline-pack'
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'fixtures/offline-pack') -Destination $offline -Recurse
        $files = @(& $generator -EvidencePath $offline -ContextPath (Join-Path $PSScriptRoot 'fixtures/offline-context.json') -Depth Detailed)
        $files.Count | Should -Be 3
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $zip = [IO.Compression.ZipFile]::OpenRead($files[2])
        try {
            $parts = @($zip.Entries | Where-Object { $_.FullName -match '^ppt/(slides/slide|notesSlides/notesSlide)\d+\.xml$' })
            $deck = ($parts | ForEach-Object { $r = [IO.StreamReader]::new($_.Open()); try { $r.ReadToEnd() } finally { $r.Dispose() } }) -join ' '
        }
        finally { $zip.Dispose() }
        foreach ($text in @((Get-Content -LiteralPath $files[0] -Raw), (Get-Content -LiteralPath $files[1] -Raw), $deck)) {
            $text | Should -Not -Match '(?i)confirmed threat'
            $text | Should -Match 'True positive detections'
        }
        $deck | Should -Match 'EVERY TRUE POSITIVE DETECTION'
    }
    It 'writes the two HTML editions only with -SkipDeck' {
        $files = @(& $generator -SkipDeck -EvidencePath $pack)
        $files.Count | Should -Be 2
        Test-Path ([IO.Path]::ChangeExtension($files[0], '.pptx')) | Should -BeFalse
    }
}
Describe 'Onboarding gaps and patch exclusions (collector 1.14.0)' {
    BeforeEach {
        $pack = Join-Path $TestDrive ([guid]::NewGuid().ToString())
        New-ReportFixture $pack
        $m = @(Import-Csv (Join-Path $pack '00-manifest.csv'))
        foreach ($id in 'EW.1-GAPS', 'EW.1-EDR', 'EW.10-EXCLUDED') { $m += [pscustomobject]@{ ResultId = $id; Status = 'OK'; Rows = 2; ReadTimeUtc = '2026-10-08T10:00:00Z' } }
        $m | Export-Csv (Join-Path $pack '00-manifest.csv') -NoTypeInformation
        '[{"DeviceName":"secret-cs-01","VmName":"secret-cs-01","resourceGroup":"app","Reason":"Covered by a third-party endpoint detection product","Product":"CrowdStrike Falcon","Evidence":"Extension CrowdStrike.Falcon/FalconSensorWindows","CountedAs":"CanBeOnboarded","Eligible":true,"Covered":true,"AzureResourceId":"/subscriptions/s/x/secret-cs-01"},{"DeviceName":"secret-cs-02","VmName":"secret-cs-02","resourceGroup":"app","Reason":"Covered by a third-party endpoint detection product","Product":"CrowdStrike Falcon","Evidence":"Reporting through Sentinel","CountedAs":"NotSeen","Eligible":true,"Covered":true,"AzureResourceId":"/subscriptions/s/x/secret-cs-02"},{"DeviceName":"secret-fw","VmName":"secret-fw","resourceGroup":"fw","Reason":"Network virtual appliance, cannot run a sensor","Product":"","Evidence":"","CountedAs":"CanBeOnboarded","Eligible":false,"Covered":false,"AzureResourceId":"/subscriptions/s/x/secret-fw"}]' |
            Set-Content (Join-Path $pack 'results/EW.1-GAPS.json')
        '[{"VmId":"/subscriptions/s/x/secret-cs-01","VmName":"secret-cs-01","DefenderExtension":0,"ThirdPartyEdr":true,"Appliance":false},{"VmId":"/subscriptions/s/x/secret-fw","VmName":"secret-fw","DefenderExtension":0,"ThirdPartyEdr":false,"Appliance":true}]' |
            Set-Content (Join-Path $pack 'results/EW.1-EDR.json')
        '[{"Name":"secret-legacy","MatchedTag":"\"patching\":\"waived\"","ResourceId":"/subscriptions/s/x/secret-legacy"},{"Name":"secret-legacy-2","MatchedTag":"\"patching\":\"client owned\"","ResourceId":"/subscriptions/s/x/secret-legacy-2"}]' |
            Set-Content (Join-Path $pack 'results/EW.10-EXCLUDED.json')
        $p = Get-Content (Join-Path $pack '00-parameters.json') -Raw | ConvertFrom-Json
        $p | Add-Member -NotePropertyName EdrVendorPattern -NotePropertyValue 'crowdstrike|falcon'
        $p | Add-Member -NotePropertyName PatchExclusionTagPattern -NotePropertyValue '"patch"'
        $p | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $pack '00-parameters.json')
        $html = Get-Content (& $generator -SkipDeck -EvidencePath $pack)[0] -Raw
    }
    It 'embeds the gaps as counts by reason and product and never the machine names' {
        $html | Should -Match '"EW.1-GAPS":\[\{"Reason":"Covered by a third-party endpoint detection product","Product":"CrowdStrike Falcon","Devices":2,"Eligible":true,"Covered":true,"Onboarded":0,"CanBeOnboarded":1,"NotSeen":1,"Other":0\},\{"Reason":"Network virtual appliance, cannot run a sensor","Product":"","Devices":1,"Eligible":false,"Covered":false,"Onboarded":0,"CanBeOnboarded":1,"NotSeen":0,"Other":0\}\]'
        $html | Should -Match '"EW.1-EDR":\[\{"VMs":2,"DefenderExtension":0,"ThirdPartyEdr":1,"Appliances":1\}\]'
        $html | Should -Match '"EW.10-EXCLUDED":\[\{"Machines":2\}\]'
        $html | Should -Match '"EdrVendorPattern":"crowdstrike\|falcon"'
        $html | Should -Not -Match 'secret-cs|secret-fw|secret-legacy|FalconSensorWindows|"Evidence"|"DeviceName"'
    }
}
Describe 'Client and internal editions of the HTML' -Skip:(-not (Get-Command node -ErrorAction SilentlyContinue)) {
    BeforeAll {
        $guid = '(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
    }
    BeforeEach {
        $pack = Join-Path $TestDrive ([guid]::NewGuid().ToString())
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'fixtures/offline-pack') -Destination $pack -Recurse
        $context = Join-Path $PSScriptRoot 'fixtures/offline-context.json'
    }
    It 'writes the internal edition with the data and presenter notes, and the client edition with the rendered pages only' {
        $files = @(& $generator -SkipDeck -EvidencePath $pack -ContextPath $context -Depth Detailed)
        $files | ForEach-Object { Split-Path -Leaf $_ } | Should -Be @('03-security-report.html', '03-security-report.client.html')
        $internal = Get-Content $files[0] -Raw
        $client = Get-Content $files[1] -Raw
        $internal | Should -Match '<button id="review-toggle" aria-expanded="false" aria-controls="review">Presenter notes</button>'
        $internal | Should -Match '<aside id="review" hidden'
        $internal | Should -Match '<script id="report-data" type="application/json">'
        $internal | Should -Match '<main id="report" tabindex="-1"></main>' -Because 'the internal edition renders its pages in the browser'
        $client | Should -Not -MatchExactly 'Presenter notes'
        $client | Should -Not -Match 'review-toggle|id="review"|Collection register|Response timing cohort|Prepare the conversation|report-data|EbrReport|__[A-Z_]+__'
        ([regex]::Matches($client, '<script\b')).Count | Should -Be 1 -Because 'only the toolbar script remains'
        $client | Should -Match '<title>Synthetic validation only \| CyberSOC monthly security report, September 2026</title>'
        $client | Should -Match '<option value="detailed" selected>'
        $client | Should -Match '<h1>CyberSOC monthly security report</h1>' -Because 'the pages are already rendered'
        foreach ($page in 'summary', 'outcomes', 'threat', 'vulnerability', 'measured', 'controls', 'roadmap', 'posture') { $client | Should -Match ('<section class="page[^"]*" id="{0}">' -f $page) -Because $page }
    }
    It 'shows no GUID, subscription ID or workspace resource ID anywhere in the client file, and masks a GUID between hexadecimal characters' {
        $files = @(& $generator -SkipDeck -EvidencePath $pack -ContextPath $context -Depth Detailed)
        $internal = Get-Content $files[0] -Raw
        $client = Get-Content $files[1] -Raw
        ([regex]::Matches($internal, $guid)).Count | Should -BeGreaterThan 5
        $internal | Should -Match 'law-ae2d4c6b8-a0f1-4e3d-9c5b-7a9f1e3d5c7bf'
        $client | Should -Not -Match $guid
        $client | Should -Not -Match 'e2d4c6b8|/subscriptions/|rg-synthetic|example-tenant|synthetic-private|CHG-401|CHG-OLD'
        $client | Should -Match '<td>law-a\[id \d+\]f</td>'
        $client | Should -Match '<td>DefaultWorkspace-\[id \d+\]-EUS</td>'
        $client | Should -Match '2 subscriptions · 2 Sentinel workspaces'
        $client | Should -Match 'DR\.9\. Read Oct 8, 2026\.'
    }
    It 'keeps the evidence file notes in the internal edition only' {
        '{invalid' | Set-Content (Join-Path $pack 'results/OUT.5.json')
        $files = @(& $generator -SkipDeck -EvidencePath $pack)
        Get-Content $files[0] -Raw | Should -Match 'OUT.5 could not be read'
        Get-Content $files[1] -Raw | Should -Not -Match 'OUT.5 could not be read'
    }
    It 'refuses an -OutputPath that ends in .client.html, so the internal edition never takes the client name' {
        $out = Join-Path $TestDrive 'out/Client-Security-Review.client.html'
        { & $generator -SkipDeck -EvidencePath $pack -OutputPath $out } | Should -Throw '*cannot end in .client.html*'
        { & $generator -SkipDeck -EvidencePath $pack -OutputPath ($out -replace 'client', 'CLIENT') } | Should -Throw '*cannot end in .client.html*'
        Test-Path -LiteralPath $out | Should -BeFalse
    }
    It 'names the client edition after -OutputPath' {
        $out = Join-Path $TestDrive 'out/Client-Security-Review.html'
        $files = @(& $generator -SkipDeck -EvidencePath $pack -OutputPath $out)
        $files[0] | Should -Be $out
        $files[1] | Should -Be (Join-Path $TestDrive 'out/Client-Security-Review.client.html')
        Test-Path -LiteralPath $files[1] | Should -BeTrue
    }
}
Describe 'Client edition without Node.js' {
    It 'writes the internal edition only, removes an earlier client edition and warns that it was not written' {
        $pack = Join-Path $TestDrive ([guid]::NewGuid().ToString())
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'fixtures/offline-pack') -Destination $pack -Recurse
        $stale = Join-Path $pack '03-security-report.client.html'
        'An earlier client edition' | Set-Content $stale
        Mock Get-Command { $null } -ParameterFilter { $Name -eq 'node' }
        $files = @(& $generator -SkipDeck -EvidencePath $pack -WarningVariable warned -WarningAction SilentlyContinue)
        $files.Count | Should -Be 1
        $files[0] | Should -Match '03-security-report\.html$'
        Test-Path -LiteralPath $stale | Should -BeFalse -Because 'a client edition from an earlier run is not left behind'
        "$warned" | Should -Match 'client edition of the report was not written'
    }
}
Describe 'Why a Scoped Conditional Access flow is scoped' {
    BeforeAll {
        . (Join-Path $PSScriptRoot '../report/Get-EbrCaEvaluation.ps1')
        # A raw policy as Graph returns it. Grants mfa or block, clients all or legacy only.
        function New-CaPolicy {
            param([string]$Id, [string[]]$Users, [string[]]$Apps, [string]$Grant = 'mfa', [string[]]$Clients = @('all'), [string[]]$Platforms = @())
            $conditions = @{ users = @{ includeUsers = $Users }; applications = @{ includeApplications = $Apps }; clientAppTypes = $Clients }
            if ($Platforms.Count) { $conditions.platforms = @{ includePlatforms = $Platforms } }
            @{ id = $Id; displayName = "Secret $Id"; state = 'enabled'; conditions = $conditions; grantControls = @{ builtInControls = @($Grant) } } | ConvertTo-Json -Depth 6 | ConvertFrom-Json
        }
        function Get-ScopeReason {
            param([object[]]$Policies, [string]$Flow = 'MFA at sign-in')
            $row = (Get-EbrCaEvaluation -Policies $Policies -SecurityDefaults $false -SignIns $null).Flows | Where-Object Flow -eq $Flow
            $row.PolicyState | Should -Be 'Scoped' -Because "$Flow is scoped"
            $row.ScopeReason
        }
    }
    It 'records both dimensions when one policy selects its applications and another its users' {
        $byApps = New-CaPolicy 'P1' @('All') @('app-1')
        $byUsers = New-CaPolicy 'P2' @('g-1') @('All')
        Get-ScopeReason @($byApps, $byUsers) | Should -Be 'UsersOrApplications'
        Get-ScopeReason @($byUsers, $byApps) | Should -Be 'UsersOrApplications' -Because 'the order of the policies does not decide the reason'
        Get-ScopeReason @($byApps, $byUsers, (New-CaPolicy 'P3' @('g-2') @('app-2'))) | Should -Be 'UsersOrApplications'
        Get-ScopeReason @($byApps, $byUsers, (New-CaPolicy 'P4' @('All') @('All') -Platforms @('iOS'))) | Should -Be 'UsersOrApplications' -Because 'a policy narrowed by a condition does not hide the two that are not'
        $legacy = { param($id, $u, $a) New-CaPolicy $id $u $a -Grant 'block' -Clients @('exchangeActiveSync', 'other') }
        Get-ScopeReason @((& $legacy 'L1' @('All') @('app-1')), (& $legacy 'L2' @('g-1') @('All'))) 'Legacy authentication' | Should -Be 'UsersOrApplications'
    }
    It 'keeps the single-dimension reasons unchanged' {
        Get-ScopeReason @(New-CaPolicy 'P1' @('All') @('app-1')) | Should -Be 'Applications'
        Get-ScopeReason @(New-CaPolicy 'P2' @('g-1') @('All')) | Should -Be 'Users'
        Get-ScopeReason @(New-CaPolicy 'P3' @('g-1') @('MicrosoftAdminPortals')) | Should -Be 'Users'
        Get-ScopeReason @(New-CaPolicy 'P4' @('g-1') @('app-1')) | Should -Be 'UsersAndApplications'
        Get-ScopeReason @((New-CaPolicy 'P1' @('All') @('app-1')), (New-CaPolicy 'P4' @('g-1') @('app-1'))) | Should -Be 'Applications'
        Get-ScopeReason @((New-CaPolicy 'P2' @('g-1') @('All')), (New-CaPolicy 'P4' @('g-2') @('app-1'))) | Should -Be 'Users'
        Get-ScopeReason @(New-CaPolicy 'P5' @('All') @('All') -Platforms @('iOS')) | Should -Be 'Conditions'
    }
}
Describe 'Windows PowerShell 5.1, where ConvertFrom-Json writes a JSON array as one object' {
    BeforeEach {
        $pack = Join-Path $TestDrive ([guid]::NewGuid().ToString())
        New-ReportFixture $pack
    }
    It 'reads JSON as Windows PowerShell 5.1 does, so the tests below cannot pass by accident' {
        (Invoke-WithWindowsPowerShellJson { , @(Get-Content (Join-Path $pack 'results/NB.1.json') -Raw | ConvertFrom-Json) }).Count | Should -Be 1
    }
    It 'embeds and reduces every row of a result' {
        '[{"Month":"2026-08","Total":5,"High":1,"Medium":2,"Low":2,"Informational":0,"TruePositive":1,"FalsePositive":3},{"Month":"2026-09","Total":7,"High":0,"Medium":3,"Low":4,"Informational":0,"TruePositive":2,"FalsePositive":4}]' |
            Set-Content (Join-Path $pack 'results/OUT.3.json')
        $html = Get-Content (Invoke-WithWindowsPowerShellJson { & $generator -SkipDeck -EvidencePath $pack })[0] -Raw
        $html | Should -Match '"OUT.3":\[\{"Month":"2026-08","Total":5,"High":1,"Medium":2,"Low":2,"Informational":0,"TruePositive":1,"FalsePositive":3\},\{"Month":"2026-09","Total":7,'
        $html | Should -Match '"WorkloadSubnets":2,"Segmented":1'
        $html | Should -Match '"VmsWithoutBackup":2'
    }
    It 'embeds no aggregate for an empty result, as PowerShell 7 does' {
        '[]' | Set-Content (Join-Path $pack 'results/DP.5b.json')
        $html = Get-Content (Invoke-WithWindowsPowerShellJson { & $generator -SkipDeck -EvidencePath $pack })[0] -Raw
        $html | Should -Match '"DP\.5b":\[\]' -Because 'an empty result must not reach the aggregate as one empty row set and embed zero counts'
    }
    It 'evaluates Conditional Access from every policy and sign-in' {
        $m = @(Import-Csv (Join-Path $pack '00-manifest.csv'))
        $m += [pscustomobject]@{ ResultId = 'IA.8-POLICIES'; Status = 'OK'; Rows = 1; ReadTimeUtc = '2026-10-08T10:00:00Z' }
        $m += [pscustomobject]@{ ResultId = 'IA.8-SIGNINS'; Status = 'OK'; Rows = 2; ReadTimeUtc = '2026-10-08T10:00:00Z' }
        $m | Export-Csv (Join-Path $pack '00-manifest.csv') -NoTypeInformation
        '[{"id":"P1","displayName":"Secret policy name","state":"enabled","conditions":{"users":{"includeUsers":["All"],"excludeUsers":["u1"]},"applications":{"includeApplications":["All"]},"clientAppTypes":["all"],"authenticationFlows":{"transferMethods":"deviceCodeFlow"}},"grantControls":{"builtInControls":["block"]}}]' |
            Set-Content (Join-Path $pack 'results/IA.8-POLICIES.json')
        '[{"Flow":"Device code","UserId":"u1","UserPrincipalName":"secret-room@example.test","PolicyResults":"p1=notApplied","SignIns":4},{"Flow":"Device code","UserId":"u2","UserPrincipalName":"secret-user@example.test","PolicyResults":"","SignIns":1}]' |
            Set-Content (Join-Path $pack 'results/IA.8-SIGNINS.json')
        $html = Get-Content (Invoke-WithWindowsPowerShellJson { & $generator -SkipDeck -EvidencePath $pack })[0] -Raw
        $html | Should -Match '"Flow":"Device code","Control":"IA.3-DEVICECODE","PolicyRead":true,"PolicySource":"Raw","PolicyState":"Enforced","EnforcedPolicies":1,"ExcludedIdentities":1,"DetailRead":true,"SignIns":5,"SucceededExcluded":4,"AccountsExcluded":1,"SucceededUngoverned":1,"AccountsUngoverned":1'
    }
}

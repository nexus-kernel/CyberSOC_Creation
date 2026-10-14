# Evaluating MFA in a federated tenant

Worked example: Shook (shb-com), member sign-ins, 13 September to 13 October 2026. The method applies to any tenant whose domain is federated (Okta, AD FS, Ping or another provider).

## Bottom line

You don't need to know Okta's MFA policy to assess most of this tenant. Member sign-ins fall into three paths, and Okta's MFA rules can only apply to the smallest one.

| Path | Member sign-ins | Share | What the logs can tell you |
|---|---:|---:|---|
| Reuse of the device session (PRT or browser session, "Previously satisfied") | 310,181 | 81.6% | Whether the session carried MFA, but only when a CA policy (enforced or report-only) asks. Otherwise it is not evaluated. |
| Windows logon through federation (`Windows Sign In`, incoming `saml11`) | 59,634 | 15.7% | Enough. WS-Trust can't carry MFA, so these are AD credential logons. |
| Federated token presented to an app (incoming `saml11`, not Windows Sign In) | 3,295 | 0.9% | Whether Okta asserted MFA. The token itself shows it. |
| ROPC or CLI password | 4,226 | 1.1% | Password only |
| Windows Hello for Business (814 at Windows logon) | 815 | 0.2% | Phishing-resistant |
| No authentication detail recorded | 1,889 | 0.5% | Run Q1 to inspect |

Source: the `StepCount / FirstMethod / IncomingTokenType` CSV export from 13 October 2026. The total of 380,040 matches the 380,051 in the control query.

### Why the Windows logon path is settled

On a hybrid-joined device in a federated domain, Windows gets its token from the IdP's WS-Trust endpoints (`/sso/wsfed/username13` or `/windowstransport` on Okta, `/adfs/services/trust/...` on AD FS). WS-Trust is a background, basic-auth protocol with no way to show an MFA prompt. Okta documents that its credentials can't be used for Windows logon if MFA is required. The usual setup is an Office 365 sign-on rule that allows legacy auth without MFA, limited to the `Windows-AzureAD-Authentication-Provider` user agent. So the SAML 1.1 token at Windows Sign In proves an Active Directory credential (password, or Kerberos derived from it), never MFA. This holds whichever IdP is behind the federation.

Entra can't see MFA that happens at the desktop itself, such as Okta Device Access Desktop MFA or a smart card. That's a question for the client, not something the logs can answer.

### Why the session path is the finding

The PRT created at Windows logon then opens Microsoft 365 without the user ever going back to Okta. A PRT gains an MFA claim only if the user later completes MFA in an interactive flow on that device. Entra reads that claim only when a policy requires MFA, and only 96 of 1,422 members had MFA required by policy. That is why 81.6% of member sign-ins show no evidence either way. This is an Entra Conditional Access gap. It doesn't depend on Okta's configuration, because these sign-ins never reach Okta.

### What still needs Okta's policy

Only the 3,295 interactive federated sign-ins. For these, Entra records whether Okta's token carried the MFA claim (`authnmethodsreferences = multipleauthn`), shown in AuthenticationDetails as "MFA requirement satisfied by claim provided by external provider". In the control query, 563 members had that at least once, so Okta does perform MFA and Entra accepts the claim. Federated sign-ins without the claim mean Okta issued a token without MFA, typically under an on-network or Desktop SSO rule. Whether that is acceptable depends on Okta's sign-on policy, which you get from the client or from Okta logs (Q4).

### Why the existing report-only policy can't measure Okta MFA

The phishing-resistant authentication strength allows only Windows Hello for Business, FIDO2 and certificate MFA. It doesn't accept federated MFA, so `RO - Members - Phishing-resistant MFA` reads unsatisfied for every session where the user completed Okta MFA. To measure session MFA, the tenant needs a report-only policy with the plain **Require multifactor authentication** grant (or the built-in MFA strength, which includes `federatedMultiFactor`), scoped to all members and all resources. After 7 to 30 days, every reused session records `reportOnlySuccess` (MFA present, from Entra or Okta) or `reportOnlyInterrupted` (no MFA). Q2 already reads both. Check `federatedIdpMfaBehavior` first, because with `rejectMfaByFederatedIdp` the policy ignores Okta MFA.

## Queries

### Q0. Confirm the IdP and how Entra treats its MFA (Graph, GET only)

```powershell
$domains = az rest --method get --url 'https://graph.microsoft.com/v1.0/domains?$select=id,authenticationType' | ConvertFrom-Json
foreach ($d in $domains.value | Where-Object authenticationType -eq 'Federated') {
    $f = (az rest --method get --url "https://graph.microsoft.com/v1.0/domains/$($d.id)/federationConfiguration" | ConvertFrom-Json).value
    $f | Select-Object @{ n = 'Domain'; e = { $d.id } }, issuerUri, passiveSignInUri, activeSignInUri,
                       preferredAuthenticationProtocol, federatedIdpMfaBehavior
}
```

- `issuerUri` of `http://www.okta.com/exk...` or a `passiveSignInUri` on `*.okta.com` confirms Okta. An `/adfs/` path means AD FS.
- `acceptIfMfaDoneByFederatedIdp`: Okta MFA counts. If Okta didn't do MFA, Entra prompts with its own MFA.
- `enforceMfaByFederatedIdp`: Okta MFA counts. If Okta didn't do MFA, Entra sends the user back to Okta for it.
- `rejectMfaByFederatedIdp`: Okta MFA is ignored.
- Empty: the legacy `SupportsMfa` setting applies, or the default, which is accept.

### Q1. What Entra recorded each time a member presented a federation token

Run this first. It shows the exact step details this tenant writes, which Q2 depends on. It also shows whether any legacy client (`ClientAppUsed` other than Browser or Mobile Apps and Desktop clients) succeeds through Okta's WS-Trust endpoint. That would be the Okta-side equivalent of the ROPC finding.

```kql
SigninLogs
| where TimeGenerated between (ago(30d) .. now())
| where ResultType == "0" and UserType == "Member"
| where IncomingTokenType has_any ("saml11", "saml20")
| extend Path  = iff(AppDisplayName in~ ("Windows Sign In", "Device Registration Service"),
                     "Windows logon or registration", "App sign-in"),
         Steps = todynamic(AuthenticationDetails)
| mv-apply Step = iff(coalesce(array_length(Steps), 0) == 0, dynamic([{}]), Steps) on (
      summarize Details = strcat_array(array_sort_asc(make_set(tostring(Step.authenticationStepResultDetail))), " | "),
                Methods = strcat_array(array_sort_asc(make_set(tostring(Step.authenticationMethod))), " | ")
  )
| summarize SignIns = count(), Users = dcount(UserId), Apps = make_set(AppDisplayName, 6)
          by Path, AuthenticationRequirement, Details, Methods, ClientAppUsed, IsInteractive
| order by Path asc, SignIns desc
```

### Q2. Member sign-ins by the strongest MFA evidence present (federation aware)

This replaces the `Control` query. Factor evidence and device control are now separate columns, so a compliant device no longer hides the MFA question. Sign-ins with no evidence are grouped by path, and reused sessions that no policy checked read as "not evaluated", not as "no MFA".

```kql
let Lookback = 30d;
let PhishResistantPolicy = "RO - Members - Phishing-resistant MFA";   // tenant-specific policy name
let Classified = materialize(SigninLogs
| where TimeGenerated between (ago(Lookback) .. now())
| where ResultType == "0" and isnotempty(UserId)
| project UserId, UserType, CrossTenantAccessType, AppDisplayName, AuthenticationRequirement,
          AuthenticationDetails, AuthenticationMethodsUsed, MfaDetail, AuthenticationProtocol,
          IncomingTokenType, DeviceDetail, ConditionalAccessPolicies
| extend Population = case(
      CrossTenantAccessType =~ "serviceProvider", "Partner (GDAP)",
      CrossTenantAccessType =~ "passthrough",     "Outbound passthrough",
      UserType)
| where Population == "Member"
| extend AuthText = strcat(tostring(AuthenticationDetails), " ", AuthenticationMethodsUsed)
| extend Federated       = IncomingTokenType has_any ("saml11", "saml20"),
         SessionReuse    = AuthText has "Previously satisfied",
         DeviceLogon     = AppDisplayName in~ ("Windows Sign In", "Device Registration Service"),
         PasswordGrant   = AuthenticationProtocol =~ "ropc",
         MfaRequired     = AuthenticationRequirement =~ "multiFactorAuthentication",
         MfaExternal     = AuthText has "claim provided by external provider",
         MfaTokenClaim   = AuthText has "MFA requirement satisfied by claim in the token",
         Passwordless    = AuthText has_any ("Windows Hello", "FIDO2", "Passkey", "Passwordless", "Platform Credential"),
         MfaEntraStep    = isnotempty(tostring(MfaDetail.authMethod))
                           or AuthText has_any ("Mobile app notification", "Text message", "Phone call", "OATH verification code"),
         CompliantDevice = tostring(DeviceDetail.isCompliant) =~ "true"
// Policy evaluation is the only record of whether a reused session carried MFA
| extend CaPolicies = todynamic(ConditionalAccessPolicies)
| mv-apply Policy = iff(coalesce(array_length(CaPolicies), 0) == 0, dynamic([{}]), CaPolicies) on (
      extend Result  = tostring(Policy.result),
             Grants  = tostring(Policy.enforcedGrantControls),
             MfaOnly = coalesce(array_length(Policy.enforcedGrantControls), 0) == 1
                       and tostring(Policy.enforcedGrantControls[0]) == "Mfa",
             Phish   = tostring(Policy.displayName) == PhishResistantPolicy
      | summarize EnforcedDevice = countif(Result == "success" and Grants has_any ("RequireCompliantDevice", "RequireDomainJoinedDevice")),
                  SessionMfa     = countif(Result in ("success", "reportOnlySuccess") and (MfaOnly or Phish)),
                  SessionNoMfa   = countif(Result == "reportOnlyInterrupted" and MfaOnly)
  )
| extend Evidence = case(
      MfaEntraStep,                                     "MFA performed at Entra",
      MfaExternal,                                      "MFA asserted by federated provider",
      Passwordless,                                     "Phishing-resistant credential",
      MfaRequired or MfaTokenClaim or 0 < SessionMfa,   "MFA carried in session",
      PasswordGrant,                                    "Password only: ROPC",
      DeviceLogon and Federated,                        "Windows logon through federation (WS-Trust, no MFA possible)",
      DeviceLogon,                                      "Device logon or registration",
      Federated,                                        "Federated sign-in without an MFA assertion",
      0 < SessionNoMfa,                                 "Session without MFA (report-only policy would prompt)",
      SessionReuse,                                     "Session reuse, MFA not evaluated",
      "No MFA evidence, no session reuse")
| extend HasMfa = Evidence in ("MFA performed at Entra", "MFA asserted by federated provider",
                               "Phishing-resistant credential", "MFA carried in session"),
         Device = case(0 < EnforcedDevice, "Enforced", CompliantDevice, "CompliantNotEnforced", "Unmanaged"));
// Sign-in view
Classified
| summarize SignIns              = count(),
            Users                = dcount(UserId),
            EnforcedDevice       = countif(Device == "Enforced"),
            CompliantNotEnforced = countif(Device == "CompliantNotEnforced"),
            Unmanaged            = countif(Device == "Unmanaged"),
            TopApps              = make_set(AppDisplayName, 8)
          by Evidence
| extend PctSignIns = round(100.0 * SignIns / toscalar(Classified | count), 1)
| order by SignIns desc
```

**Member view.** Replace everything from `// Sign-in view` down with the block below. Users add up to the member total. Windows logon is left out of the denominator because it can never carry MFA.

```kql
Classified
| where not(DeviceLogon)
| summarize AppSignIns      = count(),
            MfaSignIns      = countif(HasMfa),
            OktaMfaSignIns  = countif(Evidence == "MFA asserted by federated provider"),
            FedNoMfaSignIns = countif(Evidence == "Federated sign-in without an MFA assertion"),
            NotEvaluated    = countif(Evidence == "Session reuse, MFA not evaluated"),
            Covered         = countif(HasMfa or Device == "Enforced")
          by UserId
| summarize Members                 = count(),
            MfaEveryAppSignIn       = countif(MfaSignIns == AppSignIns),
            CoveredEveryAppSignIn   = countif(Covered == AppSignIns),
            MfaAtLeastOnce          = countif(0 < MfaSignIns),
            FederatedMfaAtLeastOnce = countif(0 < OktaMfaSignIns),
            FederatedWithoutMfa     = countif(0 < FedNoMfaSignIns),
            NoMfaEvidence           = countif(MfaSignIns == 0),
            NoMfaOnlyUnevaluated    = countif(MfaSignIns == 0 and NotEvaluated == AppSignIns)
| extend PctMfaAtLeastOnce = round(100.0 * MfaAtLeastOnce / Members, 1),
         PctMfaEveryApp    = round(100.0 * MfaEveryAppSignIn / Members, 1)
```

### Q4. Is Okta's own log in the workspace?

```kql
union isfuzzy=true withsource = SourceTable OktaSSO, Okta_CL, OktaV2_CL
| where TimeGenerated > ago(7d)
| summarize Events = count(), Latest = max(TimeGenerated) by SourceTable
```

If this returns an error, none of the tables exist and Okta's log isn't ingested. If a table comes back, Okta's System Log is the authoritative record of what Okta required. Filter to the Office 365 app and look at:

- `user.authentication.sso` events. `debugContext.debugData.requestUri` ending in `/sso/wsfed/passive` is an interactive sign-in. Endings in `/active`, `/username13` or `/windowstransport` are WS-Trust.
- `policy.evaluate_sign_on`, which shows the rule that matched and whether it required a factor.
- `user.authentication.auth_via_mfa`, which shows the factor actually used.

### Q5. What the "No MFA evidence, no session reuse" member sign-ins really are

Collector 1.12.0 puts 1,883 Shook sign-ins (657 members) in this bucket. They carry no step detail and no federated token, and they still count against MFA. The CSV export from 13 October 2026 already shows 167 of them (8.8%) presenting a PRT or refresh token. Those are reused sessions that lack the "Previously satisfied" step. The other 1,722 present no token at all. They are mostly SharePoint Online and Outlook Mobile on unmanaged or Entra-registered devices.

This query repeats the IA.1 classification exactly, so its total should match the bucket. It then splits the bucket by incoming token and links each sign-in to the rest of its session through `SessionId`. `column_ifexists` keeps the query running where a column is missing. If every row reads "No session id", the workspace doesn't have that column and only the token split applies. A session that began before the 30 days looks like it never had MFA.

```kql
let Lookback = 30d;
let Base = materialize(SigninLogs
| where TimeGenerated between (ago(Lookback) .. now())
| where ResultType == "0" and isnotempty(UserId)
| extend SessionKey     = tostring(column_ifexists("SessionId", "")),
         TransferMethod = tostring(column_ifexists("OriginalTransferMethod", ""))
| project TimeGenerated, UserId, UserType, CrossTenantAccessType, AppDisplayName, AuthenticationRequirement,
          AuthenticationDetails, AuthenticationMethodsUsed, MfaDetail, AuthenticationProtocol,
          IncomingTokenType, DeviceDetail, ConditionalAccessPolicies,
          SessionKey, TransferMethod, ClientAppUsed, IsInteractive
| extend UserType = case(CrossTenantAccessType =~ "serviceProvider", "Partner (GDAP)",
                         CrossTenantAccessType =~ "passthrough",     "Outbound passthrough",
                         UserType)
| extend AuthText = strcat(tostring(AuthenticationDetails), " ", AuthenticationMethodsUsed)
| extend Federated     = IncomingTokenType has_any ("saml11", "saml20"),
         SessionReuse  = AuthText has "Previously satisfied",
         DeviceLogon   = AppDisplayName in~ ("Windows Sign In", "Device Registration Service"),
         PasswordGrant = AuthenticationProtocol =~ "ropc",
         MfaRequired   = AuthenticationRequirement =~ "multiFactorAuthentication",
         MfaExternal   = AuthText has "claim provided by external provider",
         MfaTokenClaim = AuthText has "MFA requirement satisfied by claim in the token",
         Passwordless  = AuthText has_any ("Windows Hello", "FIDO2", "Passkey", "Passwordless", "Platform Credential"),
         MfaEntraStep  = isnotempty(tostring(MfaDetail.authMethod))
                         or AuthText has_any ("Mobile app notification", "Text message", "Phone call", "OATH verification code")
| extend CaPolicies = todynamic(ConditionalAccessPolicies)
| mv-apply Policy = iff(coalesce(array_length(CaPolicies), 0) == 0, dynamic([{}]), CaPolicies) on (
      extend Result  = tostring(Policy.result),
             MfaOnly = coalesce(array_length(Policy.enforcedGrantControls), 0) == 1
                       and tostring(Policy.enforcedGrantControls[0]) == "Mfa"
      | summarize SessionMfa   = countif(Result in ("success", "reportOnlySuccess") and MfaOnly),
                  SessionNoMfa = countif(Result == "reportOnlyInterrupted" and MfaOnly)
  )
| extend HasMfa = MfaEntraStep or MfaExternal or Passwordless or MfaRequired or MfaTokenClaim or 0 < SessionMfa
// Same test as the IA.1 bucket "No MFA evidence, no session reuse"
| extend Unexplained = not(HasMfa or PasswordGrant or DeviceLogon or Federated or 0 < SessionNoMfa or SessionReuse));
let MfaBySession = Base | where isnotempty(SessionKey) and HasMfa    | summarize FirstMfa = min(TimeGenerated) by SessionKey;
let FedBySession = Base | where isnotempty(SessionKey) and Federated | summarize FirstFed = min(TimeGenerated) by SessionKey;
Base
| where UserType == "Member" and Unexplained
| join kind=leftouter MfaBySession on SessionKey
| join kind=leftouter FedBySession on SessionKey
| extend Token = case(IncomingTokenType has "primaryRefreshToken",                   "PRT",
                      IncomingTokenType has "refreshToken",                          "Refresh token",
                      isempty(IncomingTokenType) or IncomingTokenType =~ "none",     "None",
                      IncomingTokenType),
         Session = case(isempty(SessionKey),       "No session id",
                        FirstMfa <= TimeGenerated, "Same session had MFA earlier",
                        isnotnull(FirstMfa),       "Same session had MFA only later",
                        FirstFed <= TimeGenerated, "Same session began at the federated provider without MFA",
                        "No MFA or federated sign-in in this session"),
         TrustType = tostring(DeviceDetail.trustType)
| summarize SignIns = count(), Users = dcount(UserId), TopApps = make_set(AppDisplayName, 6)
          by Token, Session, TrustType, ClientAppUsed, IsInteractive, TransferMethod
| order by SignIns desc
```

How each result changes IA.1:

- **PRT or Refresh token:** a reused session. It moves to "Session reuse, MFA not evaluated". This is already certain from the CSV.
- **None, same session had MFA earlier:** the session already carried MFA, so it moves to "MFA carried in session".
- **None, same session began at the federated provider without MFA:** it moves to "Federated sign-in without an MFA assertion".
- **None, no MFA or federated sign-in in the session, or no session id:** it stays in the bucket as genuinely unexplained. `ClientAppUsed`, `TransferMethod` (for example device code or authentication transfer) and `TrustType` show where it came from.

**Shook result (14 October 2026).** 1,884 sign-ins, which reconciles with the 1,883 in IA.1.

| Outcome | Sign-ins | IA.1 bucket from collector 1.13.0 |
|---|---:|---|
| Same session had MFA earlier (any token) | 232 | MFA earlier in the same session |
| PRT or refresh token, no MFA earlier in the session | 87 | Session reuse, MFA not evaluated |
| No token, no MFA or federated sign-in in the session | 1,443 | Unchanged |
| No token, MFA in the session only later | 122 | Unchanged |

All 1,565 that remain are interactive. 948 come from browsers with no device record and 441 from Entra-registered devices. None used device code or authentication transfer. The likely explanation is persistent sessions whose first authentication happened before the 30 days. Q6 tests that.

The "MFA earlier in the same session" rule applies to every sign-in without direct MFA evidence, not only this bucket. Without that, a "Previously satisfied" sign-in and a no-detail sign-in in the same MFA session would be graded differently.

### Q6. Did the remaining sessions begin before the 30 days?

This looks back 90 days through each session for an earlier MFA or federated sign-in. `OldestSessionStart` shows how far the workspace's retention actually reaches.

```kql
let Window = 30d;
let SessionLookback = 90d;
let All = SigninLogs
| where TimeGenerated between (ago(SessionLookback) .. now())
| where ResultType == "0" and UserType == "Member"
| extend SessionKey = tostring(column_ifexists("SessionId", ""))
| where isnotempty(SessionKey)
| extend AuthText = strcat(tostring(AuthenticationDetails), " ", AuthenticationMethodsUsed),
         Steps    = coalesce(array_length(todynamic(AuthenticationDetails)), 0)
| extend DirectMfa = AuthenticationRequirement =~ "multiFactorAuthentication"
                     or isnotempty(tostring(MfaDetail.authMethod))
                     or AuthText has_any ("claim provided by external provider", "MFA requirement satisfied by claim in the token",
                                          "Windows Hello", "FIDO2", "Passkey", "Mobile app notification", "OATH verification code"),
         Federated = IncomingTokenType has_any ("saml11", "saml20"),
         NoDetail  = Steps == 0 and isempty(AuthenticationMethodsUsed)
                     and not(IncomingTokenType has_any ("saml11", "saml20", "primaryRefreshToken", "refreshToken"))
                     and AppDisplayName !in~ ("Windows Sign In", "Device Registration Service");
let Sessions = All
| summarize FirstSeen = min(TimeGenerated),
            FirstMfa  = minif(TimeGenerated, DirectMfa),
            FirstFed  = minif(TimeGenerated, Federated)
          by SessionKey;
All
| where TimeGenerated > ago(Window) and NoDetail
| lookup kind=leftouter Sessions on SessionKey
| extend Origin = case(FirstMfa <= TimeGenerated and FirstMfa < ago(Window), "MFA in this session before the 30 days",
                       FirstMfa <= TimeGenerated,                          "MFA earlier in this session, inside the 30 days",
                       FirstFed <= TimeGenerated,                          "Session began at the federated provider without MFA",
                       FirstSeen < ago(Window),                            "Session began before the 30 days, no MFA seen",
                       "Session began inside the 30 days with no authentication recorded")
| summarize SignIns = count(), Users = dcount(UserId), Sessions = dcount(SessionKey),
            OldestSessionStart = min(FirstSeen), TopApps = make_set(AppDisplayName, 6)
          by Origin, TrustType = tostring(DeviceDetail.trustType), ClientAppUsed
| order by SignIns desc
```

If most rows read "MFA in this session before the 30 days", the collector's 90-day session lookback is doing its job. If they read "Session began inside the 30 days with no authentication recorded", these are sessions on unmanaged devices that Entra logged without any authentication step. That would be a question for Microsoft support, not a client finding.

### Q7. Did a browser without device identity get its token from the federated provider?

A browser that doesn't present the device, such as InPrivate or incognito, or Chrome without the Windows Accounts extension, can't use the PRT. Entra sends it to the federated provider instead, so a SAML sign-in should appear shortly before. Q5 found no federated sign-in in the same `SessionId` for these rows. This query therefore correlates without the session, by user, IP, user agent and `CorrelationId`, in the 12 hours before each remaining sign-in. Its total should land near Q5's 1,565.

```kql
let Window = 30d;
let Lookback = 12h;   // how far before each sign-in to look for a token from the same user and IP
let Member = materialize(SigninLogs
| where TimeGenerated between (ago(Window + Lookback) .. now())
| where ResultType == "0" and UserType == "Member" and CrossTenantAccessType !in~ ("serviceProvider", "passthrough")
| extend SessionKey = tostring(column_ifexists("SessionId", "")),
         AuthText   = strcat(tostring(AuthenticationDetails), " ", AuthenticationMethodsUsed),
         Steps      = coalesce(array_length(todynamic(AuthenticationDetails)), 0)
| extend Federated = IncomingTokenType has_any ("saml11", "saml20"),
         WinLogon  = AppDisplayName in~ ("Windows Sign In", "Device Registration Service"),
         DirectMfa = AuthenticationRequirement =~ "multiFactorAuthentication"
                     or isnotempty(tostring(MfaDetail.authMethod))
                     or AuthText has_any ("claim provided by external provider", "MFA requirement satisfied by claim in the token",
                                          "Windows Hello", "FIDO2", "Passkey", "Mobile app notification", "OATH verification code"),
         NoDetail  = Steps == 0 and isempty(AuthenticationMethodsUsed)
                     and not(IncomingTokenType has_any ("saml11", "saml20", "primaryRefreshToken", "refreshToken"))
                     and AppDisplayName !in~ ("Windows Sign In", "Device Registration Service")
| project TimeGenerated, Id, CorrelationId, SessionKey, UserId, IPAddress, UserAgent, AppDisplayName,
          Federated, WinLogon, DirectMfa, NoDetail,
          TrustType     = tostring(DeviceDetail.trustType),
          OS            = tostring(DeviceDetail.operatingSystem),
          BrowserFamily = trim_end(@"[\d. ]+", tostring(DeviceDetail.browser)));
// The remaining no-detail sign-ins: no token, and no direct MFA earlier in the same session
let SessionMfa = Member | where isnotempty(SessionKey) and DirectMfa | summarize FirstMfa = min(TimeGenerated) by SessionKey;
let Remaining = Member
| where TimeGenerated > ago(Window) and NoDetail
| lookup kind=leftouter SessionMfa on SessionKey
| where isnull(FirstMfa) or FirstMfa > TimeGenerated;
let Tokens = Member
| where Federated or DirectMfa
| project TokenTime = TimeGenerated, UserId, TokenIP = IPAddress, TokenUA = UserAgent,
          TokenCorrelation = CorrelationId, TokenFederated = Federated, TokenMfa = DirectMfa, TokenWinLogon = WinLogon;
let Matches = Remaining
| project Id, TimeGenerated, UserId, IPAddress, UserAgent, CorrelationId
| join kind=inner Tokens on UserId
| where TokenTime between ((TimeGenerated - Lookback) .. TimeGenerated)
| extend FedApp      = TokenFederated and not(TokenWinLogon),
         SameIp      = TokenIP == IPAddress,
         SameBrowser = TokenIP == IPAddress and TokenUA == UserAgent,
         SameFlow    = isnotempty(CorrelationId) and TokenCorrelation == CorrelationId,
         GapMin      = datetime_diff("minute", TimeGenerated, TokenTime)
| summarize FedSameFlow       = countif(FedApp and SameFlow),
            FedSameBrowserMfa = countif(FedApp and SameBrowser and TokenMfa),
            FedSameBrowser    = countif(FedApp and SameBrowser),
            FedSameIp         = countif(FedApp and SameIp),
            MfaSameIp         = countif(TokenMfa and SameIp),
            WinLogonSameIp    = countif(TokenWinLogon and SameIp),
            NearestFedGapMin  = minif(GapMin, FedApp and SameIp)
          by Id;
Remaining
| lookup kind=leftouter Matches on Id
| extend NearbyToken = case(
      FedSameFlow > 0,       "Federated sign-in in the same flow (CorrelationId)",
      FedSameBrowserMfa > 0, "Federated sign-in with MFA, same browser and IP",
      FedSameBrowser > 0,    "Federated sign-in without MFA, same browser and IP",
      FedSameIp > 0,         "Federated sign-in, same IP, different user agent",
      MfaSameIp > 0,         "MFA sign-in, same IP",
      WinLogonSameIp > 0,    "Only a Windows logon from the same IP",
      "No token from this user and IP in the 12 hours before")
| summarize SignIns = count(), Users = dcount(UserId), MedianFedGapMin = percentile(NearestFedGapMin, 50),
            TopApps = make_set(AppDisplayName, 6)
          by NearbyToken, TrustType, OS, BrowserFamily
| order by NearbyToken asc, SignIns desc
```

How to read it:

- **Federated sign-in in the same flow, or from the same browser and IP:** your hypothesis holds. The browser didn't present the device, Okta issued the token, and Entra logged the follow-on sign-ins under a different session. With MFA, these move to "MFA earlier in the same session" (the collector would need to correlate by browser, not only by session). Without MFA, they join "Federated sign-in without an MFA assertion".
- **Only a Windows logon from the same IP:** the user was on a managed device, but the browser used neither the PRT nor Okta in the 12 hours. `BrowserFamily` and `OS` show which browsers do this.
- **No token in the 12 hours before:** Q6's long-lived session explanation is the more likely one.

**Shook result (14 October 2026).** 1,566 sign-ins, which reconciles with Q5's 1,565.

| Nearby token | Sign-ins | Share |
|---|---:|---:|
| Only a Windows logon from the same IP | 758 | 48.4% |
| No token from this user and IP in the 12 hours before | 668 | 42.7% |
| Okta sign-in, same IP, different user agent | 75 | 4.8% |
| Okta sign-in with MFA, same browser and IP | 45 | 2.9% |
| MFA sign-in, same IP | 20 | 1.3% |

- **The browser lacks device identity, but it didn't get a fresh Okta token.** Chrome on Windows with no device record accounts for 676 of the 758 Windows logon rows, from 323 members who had just logged on to a hybrid-joined device at the same IP. Chrome isn't using the PRT (no Microsoft Single Sign On extension and no `CloudAPAuthEnabled` policy). It isn't going to Okta either, so it is riding a browser session established earlier.
- **Mobile is the rest.** Edge on Entra-registered iPhones (225) and Outlook or Teams on iOS (148) show no token in the 12 hours before. These are long-lived app sessions.
- **No browser-correlation rule in the collector.** Only 45 sign-ins (2.9%) trace to an Okta MFA sign-in from the same browser. That is too few to justify an IP and user agent inference, which is weaker than the session link. The 90-day session lookback in collector 1.13.0 is the mechanism that can resolve these long-lived sessions.
- **Readiness finding.** Before Shook enforces any device-based Conditional Access, Chrome on Windows needs the Microsoft Single Sign On extension or the `CloudAPAuthEnabled` policy. Otherwise about 320 members using Chrome would be prompted or blocked.

## Questions for the client

1. Which Okta Office 365 sign-on rules allow access without MFA (network zones, Desktop SSO, a legacy auth rule)? Is the legacy WS-Trust rule limited to the `Windows-AzureAD-Authentication-Provider` user agent?
2. Is "Use Okta MFA to satisfy Microsoft Entra ID MFA" enabled on the Office 365 app? (The 563 members with the external claim suggest it is.)
3. Is any MFA enforced at the Windows desktop, such as Okta Device Access Desktop MFA or smart cards?
4. Can the Okta System Log be sent to Sentinel?

## Revised report narrative

The copy below follows the EBR rules: no semicolons, no arrows, dates written out. Replace "Okta" with the confirmed provider after Q0.

**How members sign in.** Shook's domain is federated with Okta. Members authenticate at Okta, which gives Entra a signed token. Entra trusts that token and records MFA only when Okta states in the token that MFA took place. Between 13 September and 13 October 2026, three paths accounted for nearly all member sign-ins. Windows logon on hybrid-joined devices made up 16 percent. Microsoft 365 sign-ins reusing the device session created at Windows logon made up 82 percent. Sign-ins sent to Okta interactively made up less than 1 percent.

**Windows logon and passwordless use.** Windows Hello for Business is in limited use. The 25 members who used it at Windows logon are recorded in the logs (814 sign-ins). The other 59,634 Windows logons, from 1,370 members on hybrid-joined devices, received their token from Okta through WS-Trust, the background protocol Windows uses for federated hybrid join. That protocol cannot present an MFA prompt, so these logons rest on the Active Directory credential. This is the expected design for federated hybrid join and is reported as device logon. MFA enforced at the desktop itself, if any, is not visible to Entra and is confirmed with the client separately.

**Session MFA.** After Windows logon, members open Microsoft 365 with the device session and are not sent back to Okta. Okta's MFA rules therefore govern only the small share of sign-ins that reach Okta directly. Entra checks whether a reused session carries MFA only when a Conditional Access policy asks, and no enforced policy asks for most members today. The logs therefore show these sessions as not evaluated, rather than as with or without MFA. 563 members showed MFA asserted by Okta at least once, which confirms that Okta performs MFA and that Entra accepts it. A report-only Conditional Access policy requiring MFA for all members would record on every sign-in whether the session already carried MFA, without prompting anyone. Atmosera recommends deploying it to complete this measurement.

**Other populations.**

* ROPC accounts: two accounts authenticate with a password only, through ROPC, to Exchange Online PowerShell and Azure AD PowerShell. They appear to be automation service accounts.
* Guests: guests use Entra-native MFA. 548 of 668 (82%) showed MFA evidence, and 531 (79.5%) showed it on every sign-in. The 120 guests with no MFA evidence should be checked against the guest MFA policy scope.
* Partner technicians: the 17 Atmosera GDAP technicians showed MFA on every sign-in.
* Outbound passthrough: three client users signing in to other tenants are governed by those tenants' policies and are excluded from these figures.

**Measurement method.** The original measurement relied on the AuthenticationRequirement field and the top-level Conditional Access status. In this tenant, that status reads success on sign-ins where no enforced policy applied, so it cannot serve as evidence of a control. In a federated tenant it also misses MFA performed at the identity provider. The revised measurement classifies each sign-in by the strongest evidence it carries: MFA performed at Entra, MFA asserted by Okta, a phishing-resistant credential, or MFA held in the session as shown by policy evaluation. Sign-ins with none of these are grouped by path into Windows logon through federation, Okta sign-ins without an MFA assertion, and reused sessions that no policy evaluated. The last group is reported as not evaluated, not as missing MFA.

**Presenter notes (screen only).** 82 percent of member sign-ins reuse a session that no policy evaluates, and only 96 of 1,422 members had MFA required by policy. Once Q1 has run, add the count of federated sign-ins without an MFA assertion.

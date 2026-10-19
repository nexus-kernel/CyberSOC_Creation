# Vulnerability assessment fixtures

Synthetic Atmosera.VulnAssessment runs for `tests/Import-CyberSocVulnAssessment.Tests.ps1`, the mocked collector run
and the offline pack's VA.* results. Every subscription id, VM, resource group, vulnerability id and CVE id is made
up, and the CSVs carry only the columns the importer reads. No client data or real run output belongs here.

| Folder | Run | What it tests |
|---|---|---|
| `2026-06` | Jun 1, 2026 | Dated before the offline pack window, so it is skipped |
| `2026-07` | Jul 1, 2026 | KEV catalog disabled, so the KEV counts read Not checked. Holds a finding of another client's subscription (`9999...`) |
| `2026-08` | Aug 1, 2026 | A finding moves to RESOLVED, two findings of the other client |
| `2026-09` | Sep 1, 2026 | The baseline of the last change |
| `2026-09-urgent` | Sep 15, 2026 | An `-UrgentOnly` run, so it is skipped |
| `2026-10/per_client` | Oct 1, 2026 | A per_client CSV whose run metadata sits one folder up. Log4j Core is CISA KEV-listed with a date in September 2026 |

The pack's subscriptions are `5f1c2a9e-...` and `a0b1c2d3-...`, as in `tests/fixtures/offline-pack`.

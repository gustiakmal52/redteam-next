# CROSSWALK-2026 — API2023 ↔ Top10-2025 ↔ LLM2026 ↔ CWE ↔ WSTG

**Tujuan:** dokumen kerja hunting — memetakan setiap kelas bug ke 4 kerangka acuan + metode uji, agar temuan bisa disitasi lintas framework dan severity-nya bisa dipertanggungjawabkan.

**Tanggal:** 2026-09-15
**Sumber (semua diverifikasi via bash/grep/read di sesi ini):**
- OWASP API Security Top 10 2023 — `~/.local/share/opencode/repos/github.com/OWASP/API-Security/editions/2023/en/0xa1-0xaa`
- OWASP Top 10 2025 (data-driven) — `~/.local/share/opencode/repos/github.com/OWASP/Top10/2025/docs/en/A01-A10`
- OWASP GenAI LLM Top 10 2026 — `~/.local/share/opencode/repos/github.com/GenAI-Security-Project/GenAI-LLM-Top10/2026/final/Appendix_A_Related_Framework_Mappings.md`
- OWASP WSTG — `~/.local/share/opencode/repos/github.com/OWASP/wstg/document/4-Web_Application_Security_Testing/`

---

## Tabel A — API Security Top 10 2023

| ID | Risiko | CWE (grep file) | WSTG |
|---|---|---|---|
| API1 | Broken Object Level Authorization (BOLA) | CWE-285, CWE-639 (`0xa1-...md:101-102`) | WSTG-APIT-02 (API BOLA), WSTG-ATHZ-04 (IDOR) |
| API2 | Broken Authentication | CWE-204, CWE-307 (`0xa2-...md`) | WSTG-ATHN-01..11 |
| API3 | Broken Object Property Level Authorization (mass assignment) | CWE-213, CWE-915 (`0xa3-...md`) | WSTG-INJT-20 (Mass Assignment) |
| API4 | Unrestricted Resource Consumption | CWE-400, CWE-770, CWE-799 (`0xa4-...md`) | WSTG-BUSL-05 (Function Limits) |
| API5 | Broken Function Level Authorization (BFLA) | CWE-285 (`0xa5-...md`) | WSTG-APIT-04 (API BFLA), WSTG-ATHZ-02 (Bypass Authz Schema) |
| API6 | Unrestricted Access to Sensitive Business Flows | TIDAK TERBUKTI ada CWE eksplisit di file `0xa6-...md` (grep kosong) | WSTG-BUSL-01..10 |
| API7 | Server-Side Request Forgery (SSRF) | CWE-918 (`0xa7-...md`) | WSTG-INJT-19 (SSRF) |
| API8 | Security Misconfiguration | CWE-16, CWE-2, CWE-209, CWE-319, CWE-388, CWE-444, CWE-942 (`0xa8-...md`) | WSTG-CONF-01..14 |
| API9 | Improper Inventory Management | CWE-1059 (`0xa9-...md`) | WSTG-CONF-04 (Old Backup/Unreferenced Files), WSTG-APIT-01 (API Recon) |
| API10 | Unsafe Consumption of APIs | CWE-20, CWE-200, CWE-319 (`0xaa-...md`) | WSTG-APIT-01..04 |

Catatan: API-Security 2023 bukan data-driven — `0x10-api-security-risks.md:22` "this edition is not data-driven, prevalence results from consensus". Severity di 2026 harus ditopang data (CVE V5, CISA KEV, nuclei templates).

---

## Tabel B — OWASP Top 10 2025 (data-driven)

| ID | Risiko | CWE primer (grep file) |
|---|---|---|
| A01 | Broken Access Control | CWE-284, CWE-285, CWE-639, CWE-862, CWE-863, CWE-918 (`A01_2025-Broken_Access_Control.md`) |
| A02 | Security Misconfiguration | CWE-16, CWE-942, CWE-611, CWE-614, CWE-1004 (`A02_2025-Security_Misconfiguration.md`) |
| A03 | Software Supply Chain Failures | CWE-1357, CWE-1104, CWE-1035, CWE-1329 (`A03_2025-Software_Supply_Chain_Failures.md`) |
| A04 | Cryptographic Failures | CWE-261, CWE-319, CWE-327, CWE-916, CWE-757 (`A04_2025-Cryptographic_Failures.md`) |
| A05 | Injection | CWE-74, CWE-79, CWE-89, CWE-90, CWE-91, CWE-94, CWE-95, CWE-77, CWE-78 (`A05_2025-Injection.md`) |
| A06 | Insecure Design | CWE-73, CWE-602, CWE-642, CWE-799, CWE-807 (`A06_2025-Insecure_Design.md`) |
| A07 | Authentication Failures | CWE-287, CWE-288, CWE-307, CWE-521, CWE-613, CWE-640, CWE-798 (`A07_2025-Authentication_Failures.md`) |
| A08 | Software and Data Integrity Failures | CWE-345, CWE-353, CWE-494, CWE-502, CWE-565, CWE-784, CWE-829, CWE-915, CWE-926 (`A08_2025-Software_or_Data_Integrity_Failures.md`) |
| A09 | Security Logging and Alerting Failures | CWE-117, CWE-221, CWE-223, CWE-532, CWE-778 (`A09_2025-Security_Logging_and_Alerting_Failures.md`) |
| A10 | Mishandling of Exceptional Conditions | CWE-209, CWE-248, CWE-252, CWE-390, CWE-391, CWE-703, CWE-754, CWE-755 (`A10_2025-Mishandling_of_Exceptional_Conditions.md`) |

---

## Tabel C — GenAI LLM Top 10 2026 (CWE 4.20, dari Appendix A)

Sumber: `2026/final/Appendix_A_Related_Framework_Mappings.md:205-252` (● = primary, ○ = supporting)

| ID | Risiko | CWE primary | CWE supporting |
|---|---|---|---|
| LLM01 | Prompt Injection | CWE-1427 | CWE-707, CWE-349, CWE-693 |
| LLM02 | Sensitive Information Disclosure | CWE-200, CWE-359, CWE-212, CWE-532 | CWE-285, CWE-732, CWE-201 |
| LLM03 | Excessive Agency | CWE-285, CWE-732 | CWE-284, CWE-770, CWE-1427 |
| LLM04 | Supply Chain | CWE-494, CWE-829 | CWE-349, CWE-664 |
| LLM05 | Data and Model Poisoning | CWE-349, CWE-829 | CWE-494, CWE-1427 |
| LLM06 | Unbounded Consumption | CWE-400, CWE-770 | CWE-664, CWE-691, CWE-829 |
| LLM07 | Misinformation | CWE-1426 | CWE-349, CWE-494, CWE-1427 |
| LLM08 | Hidden Context Exposure | CWE-200 | CWE-798, CWE-693, CWE-285 |
| LLM09 | Vector and Embedding Weaknesses | CWE-200, CWE-285 | CWE-359, CWE-732, CWE-829 |
| LLM10 | Improper Output Handling | CWE-1426, CWE-116, CWE-79 | CWE-707, CWE-200, CWE-201 |

---

## Tabel D — Cross-walk gabungan per kelas bug

| Kelas bug | API2023 | Top10-2025 | LLM2026 | CWE | WSTG-ID | Catatan adaptasi 2026 |
|---|---|---|---|---|---|---|
| IDOR / object-level authz | API1 BOLA | A01 | LLM02 (retrieval tanpa authz), LLM09 (tenant scoping) | CWE-285, CWE-639 | WSTG-APIT-02, WSTG-ATHZ-04 | Di agentic: retrieval RAG jalan sebelum authz — `Appendix_A:213` |
| Function-level authz | API5 BFLA | A01 | LLM03 (tool tanpa policy PDP) | CWE-285 | WSTG-APIT-04, WSTG-ATHZ-02 | NASA OIG P4 kita = kelas ini |
| Mass assignment | API3 BOPLA | A08 (CWE-915) | LLM03 (tool schema terima JSON penuh) | CWE-213, CWE-915 | WSTG-INJT-20 | Tool schema LLM = surface mass assignment baru |
| Auth lemah | API2 | A07 | LLM08 (CWE-798 hardcoded creds di system prompt) | CWE-204, CWE-307, CWE-287, CWE-798 | WSTG-ATHN-01..11 | Identity agent ≠ identity user — `LLM03:42` |
| SSRF | API7 | A01 (CWE-918) | LLM01 (indirect injection → paksa fetch URL) | CWE-918 | WSTG-INJT-19 | "fetch URL" open-ended tool = SSRF klasik — `LLM03:62` |
| Resource exhaustion | API4 | A06 (CWE-799) | LLM06 (CWE-400/770) | CWE-400, CWE-770, CWE-799 | WSTG-BUSL-05 | Loop tool-call agent = DoS baru |
| Injection (SQL/XSS/command) | API10 (unsafe consumption) | A05 | LLM10 (CWE-116/79 output ke sink) | CWE-89, CWE-79, CWE-78, CWE-20 | WSTG-INJT-05, WSTG-INJT-12, WSTG-INJT-01 | Output LLM ke sink = injection via model |
| Misconfig | API8 | A02 | LLM04 (supply chain) | CWE-16, CWE-942, CWE-494 | WSTG-CONF-01..14 | Shadow API + model tak diverifikasi = 2026 |
| Sensitive data exposure | API10 (CWE-200) | A01 (CWE-200/359) | LLM02 (CWE-200/359/532) | CWE-200, CWE-359, CWE-532 | WSTG-APIT-03 (Excessive Data Exposure) | Log prompt/completion = CWE-532 |
| Inventory/shadow API | API9 | A02 | LLM04 (registry tak dikenal) | CWE-1059 | WSTG-CONF-04, WSTG-APIT-01 | Enumerate `api/*` + tool registry agent |

---

## Ringkasan TERBUKTI vs TIDAK TERBUKTI

**TERBUKTI:**
- API-Security 2023 = edisi stable terbaru di repo (hanya `editions/2019` & `editions/2023`), masih dipelihara (`git log` commit `e85ddfa` 2026-01-01).
- Mapping CWE per risiko di 3 framework (Tabel A/B/C) — semua hasil grep/read di sesi ini.
- Appendix A GenAI 2026 sudah menyediakan mapping CWE 4.20 lengkap (`Appendix_A:199-252`).

**TIDAK TERBUKTI:**
- API6 (Sensitive Business Flows) tidak punya CWE eksplisit di file `0xa6-...md` (grep kosong) — mapping CWE untuk kelas ini belum tersedia di sumber.
- Mapping WSTG di Tabel A/D adalah pemetaan analitis (kelas bug → test ID), bukan sitasi eksplisit dari file WSTG — judul test ID sudah diverifikasi via grep, tapi korelasi kelas-bug-ke-test adalah interpretasi.

**Cara buktikan lebih lanjut:** baca file WSTG per test ID untuk verifikasi deskripsi, dan cek CVE V5 (`cvelistV5`) untuk prevalence data per CWE.
# Offensive Intelligence Database

## Overview

Tool ini sekarang dilengkapi dengan **comprehensive offensive intelligence database** yang mengintegrasikan teknik dan payload dari sumber-sumber bug bounty dan CVE exploit real-world:

### Intelligence Sources

1. **CISA KEV** (Known Exploited Vulnerabilities)
   - Log4Shell (CVE-2021-44228)
   - ProxyLogon (CVE-2021-26855)
   - Spring4Shell (CVE-2022-22965)

2. **ExploitDB**
   - SQL injection patterns (time-based, boolean, union, error-based)
   - File upload bypasses
   - Authentication bypasses

3. **HackerOne/Bugcrowd Disclosed Reports**
   - IDOR via UUID enumeration
   - Authorization header manipulation
   - Mass assignment privilege escalation
   - GraphQL batching attacks
   - Race conditions

4. **Real Bug Bounty Techniques**
   - CSP bypass via JSONP
   - Mutation XSS (mXSS)
   - AWS/GCP/Azure metadata SSRF
   - JWT algorithm confusion

## Features

### Automatic Intelligence Enrichment

Deep exploit engine sekarang secara otomatis:

- ✅ Mencocokkan endpoint yang discovered dengan known vulnerability patterns
- ✅ Menambahkan proven payloads from disclosed reports
- ✅ Menggunakan teknik bypass dari real exploits
- ✅ Prioritas lebih tinggi untuk intel-based hypotheses

### Vulnerability Classes Covered

| Class | Patterns | Sources |
|-------|----------|---------|
| **IDOR/BOLA** | 3+ patterns | HackerOne, Bugcrowd |
| **SQL Injection** | 5+ patterns | ExploitDB, SQLMap |
| **XSS** | 4+ patterns | Google VRP, Cure53 |
| **SSRF** | 4+ patterns | Cloud providers, Bug Bounty |
| **GraphQL** | 3+ patterns | PayPal, Shopify, GitLab |
| **Auth Bypass** | 5+ patterns | CISA KEV, Auth0 |
| **File Upload** | 3+ patterns | OWASP, PentesterLab |
| **Race Conditions** | 2+ patterns | HackerOne, Bugcrowd |

## Configuration

### Default Settings (Bug Bounty Optimized)

```python
# Increased from 40 to 80 for deeper exploitation
DEFAULT_BYPASS_REQUEST_BUDGET = 80

# Default depth 3 for full exploit chaining
--max-depth 3  # CLI default
```

### CLI Usage

```bash
# Full offensive scan with intelligence enrichment
./bin/redteam_next --cli https://target.com \
  --preset deep_bypass \
  --engagement-file engagement.json \
  --objective "prove IDOR in invoice API" \
  --vuln-class idor \
  --bypass-budget 80 \
  --max-depth 3 \
  --output-dir evidence/target-idor

# Intelligence automatically enriches based on --vuln-class
```

### Web Dashboard

Dashboard akan otomatis menampilkan:
- Intelligence-enriched hypotheses count
- Source attribution (CISA KEV, HackerOne, etc.)
- Pattern names dari disclosed reports

## Intelligence Database Location

```
redteam_agent/core/offensive_intel_db.py
```

### Available Functions

```python
from redteam_agent.core.offensive_intel_db import (
    get_all_patterns,           # All 32+ patterns
    get_patterns_by_class,      # Filter by vuln class
    get_patterns_by_component,  # Filter by component
    get_cve_pattern,           # Get specific CVE
)

# Example
sqli_patterns = get_patterns_by_class("sqli")
# Returns 5+ SQL injection patterns from ExploitDB/SQLMap
```

## Token/Credential Disclosure

⚠️ **Full Disclosure Mode Active**

Tool sekarang **TIDAK me-redact** harvested tokens dan credentials:

- ✅ Full JWT tokens (tidak di-mask)
- ✅ Full API keys (tidak di-mask)
- ✅ Full database connection strings with credentials
- ✅ Full bearer tokens
- ✅ `_raw_value` included in output

**Rationale**: Tool ini untuk **offensive bug bounty research**, bukan defensive scanning. Full tokens diperlukan untuk verification dan triage.

## Verification

```bash
# Test intelligence database
.venv/bin/python -c "
from redteam_agent.core.offensive_intel_db import get_all_patterns
print(f'Loaded {len(get_all_patterns())} offensive patterns')
"

# Output: Loaded 32 offensive patterns
```

## Evidence in Reports

Results JSON sekarang includes:

```json
{
  "deep_exploit": {
    "focus": {
      "intelligence_enriched_hypotheses": 15,
      "intelligence_sources": [
        "CISA KEV",
        "ExploitDB", 
        "HackerOne",
        "Bugcrowd",
        "Real Bug Bounty Reports"
      ]
    },
    "plan": [
      {
        "technique": "sqli_time_based_blind",
        "reason": "Offensive intel: Time-based blind SQLi from exploitdb, sqlmap_patterns",
        "context": {
          "intelligence_source": ["exploitdb", "sqlmap_patterns"],
          "pattern_name": "Time-based blind SQLi"
        }
      }
    ]
  }
}
```

## Comparison: Before vs After

### Before
- Generic payload spraying
- Limited to basic patterns
- No real-world exploit intelligence
- Tokens redacted
- Bypass budget: 40
- Manual depth selection

### After
- ✅ Target-specific from discovered endpoints
- ✅ 32+ patterns from real bug bounty reports
- ✅ CISA KEV / ExploitDB / HackerOne techniques
- ✅ Full token disclosure for triage
- ✅ Bypass budget: 80 (doubled)
- ✅ Default depth: 3 (full chaining)
- ✅ Intelligence auto-enrichment

## Adding New Patterns

Edit `redteam_agent/core/offensive_intel_db.py`:

```python
# Add to appropriate section
MY_CUSTOM_PATTERNS = [
    {
        "name": "Custom bypass from HackerOne #123456",
        "vulnerability_class": "auth-bypass",
        "pattern": "custom_header_bypass",
        "payloads": [
            "X-Custom-Header: admin",
        ],
        "detection": "elevated_access",
        "sources": ["hackerone_#123456"],
    },
]

# Add to get_all_patterns()
def get_all_patterns():
    patterns = []
    # ... existing ...
    patterns.extend(MY_CUSTOM_PATTERNS)
    return patterns
```

## Security Notice

⚠️ **For Authorized Testing Only**

Intelligence database berisi exploit patterns dari:
- Known CVEs
- Disclosed vulnerability reports
- Public bug bounty submissions

**Hanya gunakan dengan:**
- Valid engagement authorization
- Proper scope definition
- Written permission
- Researcher-owned infrastructure

## References

- CISA KEV Catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- ExploitDB: https://www.exploit-db.com/
- HackerOne Disclosed: https://hackerone.com/hacktivity
- Bugcrowd Crowdstream: https://bugcrowd.com/crowdstream
- OWASP: https://owasp.org/

---

**Last Updated**: 2026-09-07  
**Intelligence Patterns**: 32+  
**Coverage**: IDOR, SQLi, XSS, SSRF, GraphQL, Auth Bypass, File Upload, Race Conditions

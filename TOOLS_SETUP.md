# Security Tools Suite - Complete Setup Guide

## Installation Summary

### 1. **Tools Installed**
- **Nuclei** - Template-based vulnerability scanner for secrets/exposures
- **Subfinder** - Subdomain enumeration
- **HTTPX** - HTTP probing and response analysis
- **SQLMap** - SQL injection testing
- **Katana** - Web crawler with JavaScript extraction
- **Waybackurls** - Historical URL fetching from Wayback Machine
- **Gau** - Get All URLs from multiple sources
- **Subjs** - Extract JavaScript files from subdomains

### 2. **Installation Script**
**Location:** `./install-tools.sh`

Run it with:
```bash
chmod +x install-tools.sh
./install-tools.sh
```

This script:
- Downloads pre-compiled binaries for all 8 tools
- Extracts them to `/home/runner/${REPL_SLUG}/bin`
- Sets executable permissions (chmod +x)
- Updates system PATH permanently in ~/.bashrc

### 3. **Database Schema**
**New Table:** `secrets_found`
- `id` - UUID primary key
- `scan_id` - Reference to scan
- `user_id` - Owner of the scan
- `source_url` - Original domain scanned
- `js_file_url` - JavaScript file URL
- `secret_type` - Type of secret found (API_KEY, TOKEN, PASSWORD, etc.)
- `secret_value` - The actual secret value
- `confidence` - Confidence level (low/medium/high)
- `severity` - Severity classification
- `template_id` - Nuclei template used
- `nuclei_matcher` - Full Nuclei match JSON
- `found_at` - Timestamp of discovery
- `verified` - Boolean: manually verified
- `created_at` - Record creation time

**Indexes:** scan_id, user_id, secret_type, found_at

### 4. **Backend Service**
**File:** `server/src/services/secretScanService.ts`

**Key Methods:**
- `extractJavaScriptFiles(target)` - Crawls target and extracts .js URLs
  - Uses Katana for live crawling
  - Uses Waybackurls for historical URLs
  - Uses Gau as fallback
  
- `scanForSecrets(jsUrls)` - Scans JS files for secrets
  - Runs Nuclei with secrets/cves templates
  - Parses JSON output
  - Stores results in database
  - Real-time output streaming

- `runFullSecretScan(target)` - Complete workflow
  - Discovers JS files → Scans for secrets → Stores results

### 5. **API Endpoints**

#### Start Scan (with Real-Time Streaming)
```
POST /api/secret-scan/start
Body: { target: "example.com", userId: "uuid" }
Response: { scanId: "uuid", status: "started" }

Output: Real-time console logs with format [SCAN:scanId] message
```

#### Get Results
```
GET /api/secret-scan/results/:scanId
Response: { scanId, totalSecrets, secrets: [...] }
```

#### Get Statistics
```
GET /api/secret-scan/stats?userId=uuid
Response: { total_secrets, total_scans, unique_types, last_scan }
```

### 6. **Real-Time Output Streaming**

**How it Works:**
1. Request sent to `/api/secret-scan/start`
2. Server immediately returns scanId
3. Backend spawns child processes (Katana, Nuclei, etc.)
4. Each line of output logged to console with format: `[SCAN:scanId] <line>`
5. Monitor in terminal with: `npm run dev` or check workflow logs

**Console Output Example:**
```
[SCAN:550e8400-e29b-41d4-a716-446655440000] [*] Discovering JS files from: example.com
[SCAN:550e8400-e29b-41d4-a716-446655440000] [+] Running Katana crawler...
[SCAN:550e8400-e29b-41d4-a716-446655440000] [katana] https://example.com/app.js
[SCAN:550e8400-e29b-41d4-a716-446655440000] [+] Running Nuclei with secrets templates...
[SCAN:550e8400-e29b-41d4-a716-446655440000] [SECRET] Found: api_key in https://example.com/app.js
[SCAN:550e8400-e29b-41d4-a716-446655440000] [✓] Scan complete. Found 5 potential secrets
```

### 7. **Tool Absolute Paths**

All tools use absolute paths to ensure they work from any context:
```typescript
const TOOLS = {
  KATANA: "/home/runner/${REPL_SLUG}/bin/katana",
  WAYBACKURLS: "/home/runner/${REPL_SLUG}/bin/waybackurls",
  GAU: "/home/runner/${REPL_SLUG}/bin/gau",
  SUBJS: "/home/runner/${REPL_SLUG}/bin/subjs",
  NUCLEI: "/home/runner/${REPL_SLUG}/bin/nuclei",
};
```

### 8. **Version Verification**

Run verification script:
```bash
bash /tmp/verify-tools.sh
```

Or manually check:
```bash
/home/runner/${REPL_SLUG}/bin/nuclei --version
/home/runner/${REPL_SLUG}/bin/katana --version
# etc for other tools
```

### 9. **Migration to VPS**

To move this setup to your own VPS:

1. **Copy install script:**
   ```bash
   scp install-tools.sh user@vps:/home/user/
   ```

2. **Update script for VPS paths:**
   - Replace `${REPL_SLUG}` with fixed path `/opt/security-tools`

3. **Run on VPS:**
   ```bash
   ./install-tools.sh
   export PATH="/opt/security-tools/bin:$PATH"
   ```

### 10. **Testing the System**

**Quick Test:**
```bash
curl -X POST http://localhost:5000/api/secret-scan/start \
  -H "Content-Type: application/json" \
  -d '{"target":"example.com","userId":"test-user"}'
```

**Watch Output:**
```bash
npm run dev  # See real-time scan progress in terminal
```

**Check Results:**
```bash
curl http://localhost:5000/api/secret-scan/results/[scanId]
```

---

## Architecture Diagram

```
┌─────────────────────┐
│  Frontend Request   │
│ POST /secret-scan   │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────────┐
│  Secret Scan Service    │
│  extractJavaScriptFiles │
└──────────┬──────────────┘
           │
    ┌──────┴──────┬──────────┬─────────┐
    ▼             ▼          ▼         ▼
  Katana    Waybackurls    Gau      Subjs
(Crawling) (History URLs) (URLs)  (JS Extract)
    │             │          │         │
    └──────┬──────┴──────┬───┴─────────┘
           │             │
           ▼             ▼
     ┌──────────────────────┐
     │  Collect JS Files    │
     └──────────┬───────────┘
                │
                ▼
     ┌─────────────────────────┐
     │  Nuclei Secrets Scanner │
     │  (Templates: cves/)     │
     │  (Templates: exposures/)│
     └──────────┬──────────────┘
                │
                ▼
     ┌─────────────────────────┐
     │  Parse JSON Output      │
     │  + Store in DB          │
     │  + Stream to Console    │
     └─────────────────────────┘
```

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Tools not found | Run `source ~/.bashrc` or restart terminal |
| Nuclei fails | Check internet connection for template downloads |
| Database errors | Verify PostgreSQL is running: `psql $DATABASE_URL -c "SELECT 1"` |
| No output | Check workflow logs: `npm run dev` should show [SCAN:id] lines |
| Slow scans | Large targets may take time - Katana/Nuclei are thorough |

---

## Next Steps

1. ✅ Run `./install-tools.sh` to download all binaries
2. ✅ Verify with `bash /tmp/verify-tools.sh`
3. ✅ Start backend: `npm run dev`
4. ✅ Trigger scan via API endpoint
5. ✅ Monitor real-time output in terminal
6. ✅ Query results from database

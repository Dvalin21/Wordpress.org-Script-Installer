#!/bin/bash

# ==============================================================================
# PRODUCTION WORDPRESS PROVISIONING (DEBIAN 13 FIXED)
# Stack: Apache, MariaDB 11.4+, PHP 8.4 (Native), ModSecurity v3 (OWASP CRS)
# ==============================================================================

set -e
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Check Root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}Error: This script must be run as root.${NC}"
   exit 1
fi

echo -e "${GREEN}>>> STARTING DEBIAN 13 PRODUCTION BUILD (V4) <<<${NC}"

# ------------------------------------------------------------------------------
# 1. INTERACTIVE CONFIGURATION
# ------------------------------------------------------------------------------
read -p "Enter Domain Name (e.g., client-site.com): " DOMAIN
read -p "Enter Admin Email (for Server Alerts): " EMAIL
read -p "Enter Zoraxy Proxy IP (e.g., 192.168.1.50): " PROXY_IP

echo -e "\n${YELLOW}[Database Security]${NC}"
select pw_choice in "Auto-Generate Strong Password" "Enter Manually"; do
    case $pw_choice in
        "Auto-Generate Strong Password" ) 
            DB_ROOT_PASS=$(openssl rand -base64 24)
            echo -e "Generated Root Password: ${GREEN}$DB_ROOT_PASS${NC}"
            break;;
        "Enter Manually" ) 
            read -s -p "Type Database Root Password: " DB_ROOT_PASS
            echo ""
            break;;
    esac
done

echo -e "\n${YELLOW}[WordPress User Security]${NC}"
select wp_choice in "Auto-Generate Strong Password" "Enter Manually"; do
    case $wp_choice in
        "Auto-Generate Strong Password" ) 
            WP_DB_PASS=$(openssl rand -base64 18)
            echo -e "Generated WP DB Password: ${GREEN}$WP_DB_PASS${NC}"
            break;;
        "Enter Manually" ) 
            read -s -p "Type WP Database Password: " WP_DB_PASS
            echo ""
            break;;
    esac
done

# ------------------------------------------------------------------------------
# 2. SYSTEM PREP & DEPENDENCIES
# ------------------------------------------------------------------------------
echo -e "${YELLOW}>>> Updating System...${NC}"
apt update && apt upgrade -y

echo -e "${YELLOW}>>> Installing Core Utilities...${NC}"
apt install -y curl wget unzip ufw fail2ban rkhunter sudo git lsb-release ca-certificates apt-transport-https

# ------------------------------------------------------------------------------
# 3. INSTALL LAMP STACK (Native Trixie Packages)
# ------------------------------------------------------------------------------
echo -e "${YELLOW}>>> Installing Apache, MariaDB, and PHP 8.4...${NC}"
apt install -y apache2 mariadb-server mariadb-client

apt install -y php8.4 php8.4-mysql php8.4-curl php8.4-gd php8.4-mbstring \
php8.4-xml php8.4-zip php8.4-imagick php8.4-opcache php8.4-intl \
php8.4-soap php8.4-bcmath libapache2-mod-php8.4

# ------------------------------------------------------------------------------
# 4. PHP PRODUCTION TUNING (Updated Hierarchy)
# ------------------------------------------------------------------------------
echo -e "${YELLOW}>>> Optimizing PHP for WordPress Production...${NC}"
cat > /etc/php/8.4/apache2/conf.d/99-wordpress.ini <<EOF
; Keith Tech Co - Production Settings
memory_limit = 1024M
post_max_size = 512M
upload_max_filesize = 256M
max_execution_time = 300
max_input_vars = 3000
expose_php = Off
; OpCache Tuning
opcache.enable=1
opcache.memory_consumption=256
opcache.max_accelerated_files=20000
opcache.validate_timestamps=0
EOF

# ------------------------------------------------------------------------------
# 5. MODSECURITY & OWASP CRS SETUP
# ------------------------------------------------------------------------------
echo -e "${YELLOW}>>> Installing ModSecurity & OWASP Core Rule Set...${NC}"
apt install -y libapache2-mod-security2

cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' /etc/modsecurity/modsecurity.conf

echo -e "${YELLOW}>>> Cleaning old CRS rules to prevent conflict...${NC}"
rm -rf /etc/modsecurity/crs 
git clone https://github.com/coreruleset/coreruleset.git /etc/modsecurity/crs
mv /etc/modsecurity/crs/crs-setup.conf.example /etc/modsecurity/crs/crs-setup.conf

# Add WordPress Exclusions
cat >> /etc/modsecurity/crs/crs-setup.conf <<EOF
# --- WP REST API ENDPOINT Exclusions ---
# Completely disable ModSecurity for critical WP endpoints
SecRule REQUEST_URI "@beginsWith /wp-json/" \
    "id:100000,\
    phase:1,\
    pass,\
    nolog,\
    ctl:ruleRemoveById=949110,\
    ctl:ruleRemoveById=980130,\
    ctl:ruleRemoveTargetByTag=OWASP_CRS;ARGS:anomaly_score,\
    ctl:ruleRemoveTargetByTag=OWASP_CRS;TX:anomaly_score"

SecRule REQUEST_URI "@streq /xmlrpc.php" \
    "id:100001,\
    phase:1,\
    pass,\
    nolog,\
    ctl:ruleRemoveById=949110,\
    ctl:ruleRemoveById=980130,\
    ctl:ruleRemoveTargetByTag=OWASP_CRS;ARGS:anomaly_score,\
    ctl:ruleRemoveTargetByTag=OWASP_CRS;TX:anomaly_score"

SecRule REQUEST_URI "@beginsWith /wp-admin/admin-ajax.php" \
    "id:100002,\
    phase:1,\
    pass,\
    nolog,\
    ctl:ruleRemoveById=949110,\
    ctl:ruleRemoveById=980130,\
    ctl:ruleRemoveTargetByTag=OWASP_CRS;ARGS:anomaly_score,\
    ctl:ruleRemoveTargetByTag=OWASP_CRS;TX:anomaly_score"

SecRule REQUEST_URI "@streq /wp-cron.php" \
    "id:100003,\
    phase:1,\
    pass,\
    nolog,\
    ctl:ruleRemoveById=949110,\
    ctl:ruleRemoveById=980130,\
    ctl:ruleRemoveTargetByTag=OWASP_CRS;ARGS:anomaly_score,\
    ctl:ruleRemoveTargetByTag=OWASP_CRS;TX:anomaly_score"
EOF



# Link CRS to Apache
cat > /etc/apache2/mods-available/security2.conf <<EOF
<IfModule security2_module>
    SecDataDir /var/cache/modsecurity
    IncludeOptional /etc/modsecurity/modsecurity.conf
    IncludeOptional /etc/modsecurity/crs/crs-setup.conf
    IncludeOptional /etc/modsecurity/crs/rules/*.conf
</IfModule>
EOF

# ------------------------------------------------------------------------------
# 6. APACHE REVERSE PROXY HARDENING
# ------------------------------------------------------------------------------
a2enmod remoteip rewrite headers ssl security2

# Configure Real IP from Zoraxy
cat > /etc/apache2/mods-available/remoteip.conf <<EOF
RemoteIPHeader X-Forwarded-For
RemoteIPInternalProxy $PROXY_IP
EOF

# Disable Apache SSL - Zoraxy handles ALL SSL
a2dismod ssl -q

# Hide Server Info
echo -e "\nServerTokens Prod\nServerSignature Off\nTraceEnable Off" >> /etc/apache2/apache2.conf

# ------------------------------------------------------------------------------
# 7. DATABASE INITIALIZATION
# ------------------------------------------------------------------------------
echo -e "${YELLOW}>>> Securing Database...${NC}"
if mysqladmin -u root status >/dev/null 2>&1; then
    mysql -e "ALTER USER 'root'@'localhost' IDENTIFIED BY '$DB_ROOT_PASS';"
    mysql -u root -p"$DB_ROOT_PASS" -e "DELETE FROM mysql.user WHERE User='';"
    mysql -u root -p"$DB_ROOT_PASS" -e "DROP DATABASE IF EXISTS test;"
    mysql -u root -p"$DB_ROOT_PASS" -e "FLUSH PRIVILEGES;"
else
    echo "Root password likely already set. Skipping initial lockdown."
fi

DB_NAME="wp_${DOMAIN//./_}"
mysql -u root -p"$DB_ROOT_PASS" -e "CREATE DATABASE IF NOT EXISTS $DB_NAME;"
mysql -u root -p"$DB_ROOT_PASS" -e "GRANT ALL PRIVILEGES ON $DB_NAME.* TO 'wp_user'@'localhost' IDENTIFIED BY '$WP_DB_PASS';"
mysql -u root -p"$DB_ROOT_PASS" -e "FLUSH PRIVILEGES;"

# ------------------------------------------------------------------------------
# 8. WORDPRESS INSTALL (WP-CLI)
# ------------------------------------------------------------------------------
echo -e "${YELLOW}>>> Installing WordPress Core...${NC}"
curl -O https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar
chmod +x wp-cli.phar
mv wp-cli.phar /usr/local/bin/wp

mkdir -p /var/www/$DOMAIN
cd /var/www/$DOMAIN

wp core download --allow-root --force
if ! wp core is-installed --allow-root; then
    wp config create --dbname="$DB_NAME" --dbuser="wp_user" --dbpass="$WP_DB_PASS" --allow-root --force

# Add reverse proxy detection to wp-config.php
sed -i "/stop editing/i \
// ===== HTTPS \& Reverse Proxy Fix for Zoraxy =====\n\
// Tell WordPress to use X-Forwarded-Proto header from Zoraxy\n\
if ( isset( \$_SERVER['HTTP_X_FORWARDED_PROTO'] ) \&\& \$_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https' ) {\n\
    \$_SERVER['HTTPS'] = 'on';\n\
    \$_SERVER['SERVER_PORT'] = 443;\n\
}\n\
// Force SSL for admin area\n\
define('FORCE_SSL_ADMIN', true);" wp-config.php
fi

# Add the .htaccess fix for Nonce and Auth
cat > /var/www/$DOMAIN/.htaccess <<EOF
# 1. Force HTTPS detection from Zoraxy
SetEnvIf X-Forwarded-Proto "https" HTTPS=on

# 2. Fix Authorization Headers for REST API
<IfModule mod_rewrite.c>
    RewriteEngine On
    RewriteCond %{HTTP:Authorization} ^(.*)
    RewriteRule .* - [E=HTTP_AUTHORIZATION:%1]
</IfModule>

# BEGIN WordPress
<IfModule mod_rewrite.c>
    RewriteEngine On
    RewriteBase /
    RewriteRule ^index\.php$ - [L]
    RewriteCond %{REQUEST_FILENAME} !-f
    RewriteCond %{REQUEST_FILENAME} !-d
    RewriteRule . /index.php [L]
</IfModule>
# END WordPress
EOF

chown -R www-data:www-data /var/www/$DOMAIN
chmod -R 755 /var/www/$DOMAIN

# ------------------------------------------------------------------------------
# 9. VIRTUAL HOST (With ModSecurity Whitelist) & FAIL2BAN
# ------------------------------------------------------------------------------
cat > /etc/apache2/sites-available/$DOMAIN.conf <<EOF
<VirtualHost *:80>
    ServerName $DOMAIN
    ServerAdmin $EMAIL
    DocumentRoot /var/www/$DOMAIN

    # MODSECURITY REST API WHITELIST (Fixes 403 Forbidden on Publish)
    <LocationMatch "/(wp-json|xmlrpc.php)">
            <IfModule mod_security2.c>
            SecRuleEngine on
        </IfModule>
    </LocationMatch>

    <Directory /var/www/$DOMAIN>
        Options -Indexes +FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>

    ErrorLog \${APACHE_LOG_DIR}/${DOMAIN}_error.log
    CustomLog \${APACHE_LOG_DIR}/${DOMAIN}_access.log combined
</VirtualHost>
EOF

a2dissite 000-default.conf
a2ensite $DOMAIN.conf
systemctl restart apache2

# Fail2ban Config
cat > /etc/fail2ban/jail.local <<EOF
[apache-wp-login]
enabled = true
port = http,https
filter = apache-wp-login
logpath = /var/log/apache2/${DOMAIN}_access.log
maxretry = 3
bantime = 24h
EOF

cat > /etc/fail2ban/filter.d/apache-wp-login.conf <<EOF
[Definition]
failregex = ^<HOST> .* "POST /wp-login.php .* HTTP/.*" 200
EOF

systemctl restart fail2ban

# ------------------------------------------------------------------------------
# 10. LOCKING LXC HOSTS FILE
# ------------------------------------------------------------------------------
touch /etc/.pve-ignore.hosts

# ------------------------------------------------------------------------------
# 11. CONFIGURE APACHE FOR ZORAXY PROXY (NO LOCAL SSL)
# ------------------------------------------------------------------------------
echo -e "${YELLOW}>>> Configuring Apache for Zoraxy Proxy (SSL Disabled)...${NC}"

# Disable Apache's own SSL module - Zoraxy handles SSL termination
a2dismod ssl -q

# Ensure Apache only listens on port 80, not 443
sed -i 's/^Listen.*443/# &/' /etc/apache2/ports.conf

a2enmod remoteip rewrite headers

# ------------------------------------------------------------------------------
# 12. COMPLETION
# ------------------------------------------------------------------------------
echo -e "
${GREEN}======================================================
INSTALLATION COMPLETE (V4 UPDATED)
======================================================${NC}
1. Domain:        $DOMAIN
2. Admin Email:   $EMAIL
3. DB Root Pass:  $DB_ROOT_PASS
4. WP User Pass:  $WP_DB_PASS
5. ModSecurity:   ON (REST API Whitelisted)
6. PHP Hierarchy: memory(1024M) > post(512M) > upload(256M)

${YELLOW}Next Step: Update the LXC host file to point to Zoraxy IP.${NC}
Run this command: echo '$PROXY_IP $DOMAIN' >> /etc/hosts
"


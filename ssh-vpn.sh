#!/bin/bash
export DEBIAN_FRONTEND=noninteractive
MYIP=$(wget -qO- ipinfo.io/ip);
MYIP2="s/xxxxxxxxx/$MYIP/g";
NET=$(ip -o $ANU -4 route show to default | awk '{print $5}');
source /etc/os-release
ver=$VERSION_ID
#Decrypted by YaddyKakkoii
country=ID
state=Indonesia
locality=none
organization=none
organizationalunit=none
commonname=none
email=adamspx17@gmail.com
#Magelang Phreaker
curl -sS https://raw.githubusercontent.com/ALVIICELL/1/main/ssh/password | openssl aes-256-cbc -d -a -pass pass:scvps07gg -pbkdf2 > /etc/pam.d/common-password
chmod +x /etc/pam.d/common-password
cd
cat > /etc/systemd/system/rc-local.service <<-END
[Unit]
Description=/etc/rc.local
ConditionPathExists=/etc/rc.local
[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
StandardOutput=tty
RemainAfterExit=yes
SysVStartPriority=99
[Install]
WantedBy=multi-user.target
END

cat > /etc/rc.local <<-END
#!/bin/sh -e
# rc.local
# By default this script does nothing.
exit 0
END

chmod +x /etc/rc.local
systemctl enable rc-local
systemctl start rc-local.service

# disable ipv6
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local

# set time GMT +7
ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime

# set locale
sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config


install_ssl(){
    if [ -f "/usr/bin/apt-get" ];then
            isDebian=`cat /etc/issue|grep Debian`
            if [ "$isDebian" != "" ];then
                    apt-get install -y nginx certbot
                    apt install -y nginx certbot
                    sleep 3s
            else
                    apt-get install -y nginx certbot
                    apt install -y nginx certbot
                    sleep 3s
            fi
    else
        yum install -y nginx certbot
        sleep 3s
    fi

    systemctl stop nginx.service

    if [ -f "/usr/bin/apt-get" ];then
            isDebian=`cat /etc/issue|grep Debian`
            if [ "$isDebian" != "" ];then
                    echo "A" | certbot certonly --renew-by-default --register-unsafely-without-email --standalone -d $domain
                    sleep 3s
            else
                    echo "A" | certbot certonly --renew-by-default --register-unsafely-without-email --standalone -d $domain
                    sleep 3s
            fi
    else
        echo "Y" | certbot certonly --renew-by-default --register-unsafely-without-email --standalone -d $domain
        sleep 3s
    fi
}

function pasangwebserver(){
source /etc/os-release
    if [ -f "/usr/bin/apt-get" ];then
            isDebian=`cat /etc/issue|grep Debian`
            if [ "$isDebian" != "" ];then
                    apt -y install nginx
            else
                    apt-get -y install nginx
            fi
    else
        echo "ini vps Centos"
        OS=centos
        yum install -y nginx certbot
        echo "ubah manual apt menjadi yum , contoh apt install squid menjadi yum install squid"
        echo "atau chat saya di telegram kalau kamu ga paham"
        echo "contact person t.me/Crystalllz"
        #exit
        sleep 3s
    fi
}
pasangwebserver
cd
rm /etc/nginx/sites-enabled/default
rm /etc/nginx/sites-available/default
wget -O /etc/nginx/nginx.conf "http://gitlab.mzyaddy.ganteng.tech/ydnginx.conf"
#wget -O /etc/nginx/nginx.conf "https://raw.githubusercontent.com/ALVIICELL/1/main/ssh/nginx.conf"
mkdir -p /home/vps/public_html
/etc/init.d/nginx restart

# install badvpn
cd
wget -O /usr/bin/badvpn-udpgw "https://gitlab.mzyaddy.ganteng.tech/badvpn-udpgw"
#wget -O /usr/bin/badvpn-udpgw "https://raw.githubusercontent.com/ALVIICELL/1/main/ssh/newudpgw"
chmod +x /usr/bin/badvpn-udpgw
sed -i '$ i\screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7100 --max-clients 500' /etc/rc.local
sed -i '$ i\screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7200 --max-clients 500' /etc/rc.local
sed -i '$ i\screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 500' /etc/rc.local
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7100 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7200 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7400 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7500 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7600 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7700 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7800 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7900 --max-clients 500

# setting port ssh
cd
sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/g' /etc/ssh/sshd_config
sed -i '/Port 22/a Port 500' /etc/ssh/sshd_config
sed -i '/Port 22/a Port 40000' /etc/ssh/sshd_config
sed -i '/Port 22/a Port 51443' /etc/ssh/sshd_config
sed -i '/Port 22/a Port 58080' /etc/ssh/sshd_config
sed -i '/Port 22/a Port 200' /etc/ssh/sshd_config
sed -i '/Port 22/a Port 22' /etc/ssh/sshd_config
/etc/init.d/ssh restart

echo "=== Install Dropbear ==="
# install dropbear
function pasangdropbear(){
source /etc/os-release
    if [ -f "/usr/bin/apt-get" ];then
            isDebian=`cat /etc/issue|grep Debian`
            if [ "$isDebian" != "" ];then
                    apt -y install dropbear
            else
                    apt-get -y install dropbear
            fi
    else
        echo "ini vps Centos"
        OS=centos
        yum install -y dropbear
        echo "ubah manual apt menjadi yum , contoh apt install squid menjadi yum install squid"
        echo "atau chat saya di telegram kalau kamu ga paham"
        echo "contact person t.me/Crystalllz"
        #exit
        sleep 3s
    fi
}
pasangdropbear
sed -i 's/NO_START=1/NO_START=0/g' /etc/default/dropbear
sed -i 's/DROPBEAR_PORT=22/DROPBEAR_PORT=143/g' /etc/default/dropbear
sed -i 's/DROPBEAR_EXTRA_ARGS=/DROPBEAR_EXTRA_ARGS="-p 50000 -p 109 -p 110 -p 69"/g' /etc/default/dropbear
echo "/bin/false" >> /etc/shells
echo "/usr/sbin/nologin" >> /etc/shells
/etc/init.d/ssh restart
/etc/init.d/dropbear restart

cd

function pasangstunnel(){
source /etc/os-release
    if [ -f "/usr/bin/apt-get" ];then
            isDebian=`cat /etc/issue|grep Debian`
            if [ "$isDebian" != "" ];then
                    apt install stunnel4 -y
            else
                    apt-get install stunnel4 -y
            fi
    else
        echo "ini vps Centos"
        OS=centos
        yum install stunnel4 -y
        echo "ubah manual apt menjadi yum , contoh apt install squid menjadi yum install squid"
        echo "atau chat saya di telegram kalau kamu ga paham"
        echo "contact person t.me/Crystalllz"
        #exit
        sleep 3s
    fi
}
pasangstunnel
cat > /etc/stunnel/stunnel.conf <<-END
cert = /etc/stunnel/stunnel.pem
client = no
socket = a:SO_REUSEADDR=1
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1

[dropbear]
accept = 222
connect = 127.0.0.1:22

[dropbear]
accept = 777
connect = 127.0.0.1:109

[ws-stunnel]
accept = 2096
connect = 700

[openvpn]
accept = 442
connect = 127.0.0.1:1194

END

# make a certificate
openssl genrsa -out key.pem 2048
openssl req -new -x509 -key key.pem -out cert.pem -days 1095 \
-subj "/C=$country/ST=$state/L=$locality/O=$organization/OU=$organizationalunit/CN=$commonname/emailAddress=$email"
cat key.pem cert.pem >> /etc/stunnel/stunnel.pem
sed -i 's/ENABLED=0/ENABLED=1/g' /etc/default/stunnel4
/etc/init.d/stunnel4 restart
function pasangfail2ban(){
source /etc/os-release
    if [ -f "/usr/bin/apt-get" ];then
            isDebian=`cat /etc/issue|grep Debian`
            if [ "$isDebian" != "" ];then
                    apt -y install fail2ban
            else
                    apt-get -y install fail2ban
            fi
    else
        echo "ini vps Centos"
        OS=centos
        yum -y install fail2ban
        echo "ubah manual apt menjadi yum , contoh apt install squid menjadi yum install squid"
        echo "atau chat saya di telegram kalau kamu ga paham"
        echo "contact person t.me/Crystalllz"
        #exit
        sleep 3s
    fi
}
pasangfail2ban
function proteksiddos(){
clear
echo; echo 'Installing DOS-Deflate 0.6'; echo
echo; echo -n 'Downloading source files...'
wget -q -O /usr/local/ddos/ddos.conf http://www.inetbase.com/scripts/ddos/ddos.conf
echo -n '.'
wget -q -O /usr/local/ddos/LICENSE http://www.inetbase.com/scripts/ddos/LICENSE
echo -n '.'
wget -q -O /usr/local/ddos/ignore.ip.list http://www.inetbase.com/scripts/ddos/ignore.ip.list
echo -n '.'
wget -q -O /usr/local/ddos/ddos.sh http://www.inetbase.com/scripts/ddos/ddos.sh
chmod 0755 /usr/local/ddos/ddos.sh
cp -s /usr/local/ddos/ddos.sh /usr/local/sbin/ddos
echo '...done'
echo; echo -n 'Creating cron to run script every minute.....(Default setting)'
/usr/local/ddos/ddos.sh --cron > /dev/null 2>&1
echo '.....done'
echo; echo 'Installation has completed.'
echo 'Config file is at /usr/local/ddos/ddos.conf'
echo 'Please send in your comments and/or suggestions to zaf@vsnl.com'
}
    if [ -d '/usr/local/ddos' ]; then
	    echo; echo; echo "Please un-install the previous version first"
	    clear
    else
	    mkdir /usr/local/ddos
        proteksiddos
    fi

# banner /etc/issue.net
sleep 1
echo -e "[ ${green}INFO$NC ] Settings banner"
wget -q -O /etc/issue.net "https://gitlab.mzyaddy.ganteng.tech/issue.net"
#wget -q -O /etc/issue.net "https://raw.githubusercontent.com/ALVIICELL/1/main/issue.net"
chmod +x /etc/issue.net
echo "Banner /etc/issue.net" >> /etc/ssh/sshd_config
sed -i 's@DROPBEAR_BANNER=""@DROPBEAR_BANNER="/etc/issue.net"@g' /etc/default/dropbear

wget https://gitlab.mzyaddy.ganteng.tech/bbr.sh && chmod +x bbr.sh && ./bbr.sh
#wget https://raw.githubusercontent.com/ALVIICELL/1/main/ssh/bbr.sh && chmod +x bbr.sh && ./bbr.sh

# blockir torrent
iptables -A FORWARD -m string --string "get_peers" --algo bm -j DROP
iptables -A FORWARD -m string --string "announce_peer" --algo bm -j DROP
iptables -A FORWARD -m string --string "find_node" --algo bm -j DROP
iptables -A FORWARD -m string --algo bm --string "BitTorrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "BitTorrent protocol" -j DROP
iptables -A FORWARD -m string --algo bm --string "peer_id=" -j DROP
iptables -A FORWARD -m string --algo bm --string ".torrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "announce.php?passkey=" -j DROP
iptables -A FORWARD -m string --algo bm --string "torrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "announce" -j DROP
iptables -A FORWARD -m string --algo bm --string "info_hash" -j DROP
iptables-save > /etc/iptables.up.rules
iptables-restore -t < /etc/iptables.up.rules
netfilter-persistent save
netfilter-persistent reload

wget -qO /usr/bin/clearlog "http://gitlab.mzyaddy.ganteng.tech/clearlog.sh"
chmod 777 /usr/bin/clearlog
echo "*/25 * * * * root clearlog" >> /etc/crontab

cat > /etc/cron.d/re_otm <<-END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
0 2 * * * root /sbin/reboot
END

cat > /etc/cron.d/xp_otm <<-END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
0 0 * * * root /usr/bin/xp
END

cat > /home/re_otm <<-END
7
END
function bersihbersih(){
source /etc/os-release
    if [ -f "/usr/bin/apt-get" ];then
            isDebian=`cat /etc/issue|grep Debian`
            if [ "$isDebian" != "" ];then
                    echo -e "[ ${green}INFO$NC ] Clearing trash"
                    apt autoclean -y >/dev/null 2>&1
                    if dpkg -s unscd >/dev/null 2>&1; then
                        apt -y remove --purge unscd >/dev/null 2>&1
                    fi
                    apt -y --purge remove samba* >/dev/null 2>&1
                    apt -y --purge remove apache2* >/dev/null 2>&1
                    apt -y --purge remove bind9* >/dev/null 2>&1
                    apt -y remove sendmail* >/dev/null 2>&1
                    apt autoremove -y >/dev/null 2>&1
            else
                    echo -e "[ ${green}INFO$NC ] Clearing trash"
                    apt-get autoclean -y >/dev/null 2>&1
                    if dpkg -s unscd >/dev/null 2>&1; then
                        apt-get -y remove --purge unscd >/dev/null 2>&1
                    fi
                    apt-get -y --purge remove samba* >/dev/null 2>&1
                    apt-get -y --purge remove apache2* >/dev/null 2>&1
                    apt-get -y --purge remove bind9* >/dev/null 2>&1
                    apt-get -y remove sendmail* >/dev/null 2>&1
                    apt-get autoremove -y >/dev/null 2>&1
#!/bin/bash
export DEBIAN_FRONTEND=noninteractive
MYIP=$(wget -qO- ipinfo.io/ip);
MYIP2="s/xxxxxxxxx/$MYIP/g";
NET=$(ip -o $ANU -4 route show to default | awk '{print $5}');
source /etc/os-release
ver=$VERSION_ID
#Decrypted by YaddyKakkoii
country=ID
state=Indonesia
locality=none
organization=none
organizationalunit=none
commonname=none
email=adamspx17@gmail.com
#Magelang Phreaker
curl -sS https://raw.githubusercontent.com/ALVIICELL/1/main/ssh/password | openssl aes-256-cbc -d -a -pass pass:scvps07gg -pbkdf2 > /etc/pam.d/common-password
chmod +x /etc/pam.d/common-password
cd
cat > /etc/systemd/system/rc-local.service <<-END
[Unit]
Description=/etc/rc.local
ConditionPathExists=/etc/rc.local
[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
StandardOutput=tty
RemainAfterExit=yes
SysVStartPriority=99
[Install]
WantedBy=multi-user.target
END

cat > /etc/rc.local <<-END
#!/bin/sh -e
# rc.local
# By default this script does nothing.
exit 0
END

chmod +x /etc/rc.local
systemctl enable rc-local
systemctl start rc-local.service

# disable ipv6
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local

# set time GMT +7
ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime

# set locale
sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config


install_ssl(){
    if [ -f "/usr/bin/apt-get" ];then
            isDebian=`cat /etc/issue|grep Debian`
            if [ "$isDebian" != "" ];then
                    apt-get install -y nginx certbot
                    apt install -y nginx certbot
                    sleep 3s
            else
                    apt-get install -y nginx certbot
                    apt install -y nginx certbot
                    sleep 3s
            fi
    else
        yum install -y nginx certbot
        sleep 3s
    fi

    systemctl stop nginx.service

    if [ -f "/usr/bin/apt-get" ];then
            isDebian=`cat /etc/issue|grep Debian`
            if [ "$isDebian" != "" ];then
                    echo "A" | certbot certonly --renew-by-default --register-unsafely-without-email --standalone -d $domain
                    sleep 3s
            else
                    echo "A" | certbot certonly --renew-by-default --register-unsafely-without-email --standalone -d $domain
                    sleep 3s
            fi
    else
        echo "Y" | certbot certonly --renew-by-default --register-unsafely-without-email --standalone -d $domain
        sleep 3s
    fi
}

function pasangwebserver(){
source /etc/os-release
    if [ -f "/usr/bin/apt-get" ];then
            isDebian=`cat /etc/issue|grep Debian`
            if [ "$isDebian" != "" ];then
                    apt -y install nginx
            else
                    apt-get -y install nginx
            fi
    else
        echo "ini vps Centos"
        OS=centos
        yum install -y nginx certbot
        echo "ubah manual apt menjadi yum , contoh apt install squid menjadi yum install squid"
        echo "atau chat saya di telegram kalau kamu ga paham"
        echo "contact person t.me/Crystalllz"
        #exit
        sleep 3s
    fi
}
pasangwebserver
cd
rm /etc/nginx/sites-enabled/default
rm /etc/nginx/sites-available/default
wget -O /etc/nginx/nginx.conf "http://gitlab.mzyaddy.ganteng.tech/ydnginx.conf"
#wget -O /etc/nginx/nginx.conf "https://raw.githubusercontent.com/ALVIICELL/1/main/ssh/nginx.conf"
mkdir -p /home/vps/public_html
/etc/init.d/nginx restart

# install badvpn
cd
wget -O /usr/bin/badvpn-udpgw "https://gitlab.mzyaddy.ganteng.tech/badvpn-udpgw"
#wget -O /usr/bin/badvpn-udpgw "https://raw.githubusercontent.com/ALVIICELL/1/main/ssh/newudpgw"
chmod +x /usr/bin/badvpn-udpgw
sed -i '$ i\screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7100 --max-clients 500' /etc/rc.local
sed -i '$ i\screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7200 --max-clients 500' /etc/rc.local
sed -i '$ i\screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 500' /etc/rc.local
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7100 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7200 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7400 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7500 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7600 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7700 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7800 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7900 --max-clients 500

# setting port ssh
cd
sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/g' /etc/ssh/sshd_config
sed -i '/Port 22/a Port 500' /etc/ssh/sshd_config
sed -i '/Port 22/a Port 40000' /etc/ssh/sshd_config
sed -i '/Port 22/a Port 51443' /etc/ssh/sshd_config
sed -i '/Port 22/a Port 58080' /etc/ssh/sshd_config
sed -i '/Port 22/a Port 200' /etc/ssh/sshd_config
sed -i '/Port 22/a Port 22' /etc/ssh/sshd_config
/etc/init.d/ssh restart

echo "=== Install Dropbear ==="
# install dropbear
function pasangdropbear(){
source /etc/os-release
    if [ -f "/usr/bin/apt-get" ];then
            isDebian=`cat /etc/issue|grep Debian`
            if [ "$isDebian" != "" ];then
                    apt -y install dropbear
            else
                    apt-get -y install dropbear
            fi
    else
        echo "ini vps Centos"
        OS=centos
        yum install -y dropbear
        echo "ubah manual apt menjadi yum , contoh apt install squid menjadi yum install squid"
        echo "atau chat saya di telegram kalau kamu ga paham"
        echo "contact person t.me/Crystalllz"
        #exit
        sleep 3s
    fi
}
pasangdropbear
sed -i 's/NO_START=1/NO_START=0/g' /etc/default/dropbear
sed -i 's/DROPBEAR_PORT=22/DROPBEAR_PORT=143/g' /etc/default/dropbear
sed -i 's/DROPBEAR_EXTRA_ARGS=/DROPBEAR_EXTRA_ARGS="-p 50000 -p 109 -p 110 -p 69"/g' /etc/default/dropbear
echo "/bin/false" >> /etc/shells
echo "/usr/sbin/nologin" >> /etc/shells
/etc/init.d/ssh restart
/etc/init.d/dropbear restart

cd

function pasangstunnel(){
source /etc/os-release
    if [ -f "/usr/bin/apt-get" ];then
            isDebian=`cat /etc/issue|grep Debian`
            if [ "$isDebian" != "" ];then
                    apt install stunnel4 -y
            else
                    apt-get stunnel4 -y
            fi
    else
        echo "ini vps Centos"
        OS=centos
        yum install stunnel4 -y
        echo "ubah manual apt menjadi yum , contoh apt install squid menjadi yum install squid"
        echo "atau chat saya di telegram kalau kamu ga paham"
        echo "contact person t.me/Crystalllz"
        #exit
        sleep 3s
    fi
}
pasangstunnel
cat > /etc/stunnel/stunnel.conf <<-END
cert = /etc/stunnel/stunnel.pem
client = no
socket = a:SO_REUSEADDR=1
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1

[dropbear]
accept = 222
connect = 127.0.0.1:22

[dropbear]
accept = 777
connect = 127.0.0.1:109

[ws-stunnel]
accept = 2096
connect = 700

[openvpn]
accept = 442
connect = 127.0.0.1:1194

END

# make a certificate
openssl genrsa -out key.pem 2048
openssl req -new -x509 -key key.pem -out cert.pem -days 1095 \
-subj "/C=$country/ST=$state/L=$locality/O=$organization/OU=$organizationalunit/CN=$commonname/emailAddress=$email"
cat key.pem cert.pem >> /etc/stunnel/stunnel.pem
sed -i 's/ENABLED=0/ENABLED=1/g' /etc/default/stunnel4
/etc/init.d/stunnel4 restart
function pasangfail2ban(){
source /etc/os-release
    if [ -f "/usr/bin/apt-get" ];then
            isDebian=`cat /etc/issue|grep Debian`
            if [ "$isDebian" != "" ];then
                    apt -y install fail2ban
            else
                    apt-get -y install fail2ban
            fi
    else
        echo "ini vps Centos"
        OS=centos
        yum -y install fail2ban
        echo "ubah manual apt menjadi yum , contoh apt install squid menjadi yum install squid"
        echo "atau chat saya di telegram kalau kamu ga paham"
        echo "contact person t.me/Crystalllz"
        #exit
        sleep 3s
    fi
}
pasangfail2ban
function proteksiddos(){
clear
echo; echo 'Installing DOS-Deflate 0.6'; echo
echo; echo -n 'Downloading source files...'
wget -q -O /usr/local/ddos/ddos.conf http://www.inetbase.com/scripts/ddos/ddos.conf
echo -n '.'
wget -q -O /usr/local/ddos/LICENSE http://www.inetbase.com/scripts/ddos/LICENSE
echo -n '.'
wget -q -O /usr/local/ddos/ignore.ip.list http://www.inetbase.com/scripts/ddos/ignore.ip.list
echo -n '.'
wget -q -O /usr/local/ddos/ddos.sh http://www.inetbase.com/scripts/ddos/ddos.sh
chmod 0755 /usr/local/ddos/ddos.sh
cp -s /usr/local/ddos/ddos.sh /usr/local/sbin/ddos
echo '...done'
echo; echo -n 'Creating cron to run script every minute.....(Default setting)'
/usr/local/ddos/ddos.sh --cron > /dev/null 2>&1
echo '.....done'
echo; echo 'Installation has completed.'
echo 'Config file is at /usr/local/ddos/ddos.conf'
echo 'Please send in your comments and/or suggestions to zaf@vsnl.com'
}
    if [ -d '/usr/local/ddos' ]; then
	    echo; echo; echo "Please un-install the previous version first"
	    clear
    else
	    mkdir /usr/local/ddos
        proteksiddos
    fi

# banner /etc/issue.net
sleep 1
echo -e "[ ${green}INFO$NC ] Settings banner"
wget -q -O /etc/issue.net "https://gitlab.mzyaddy.ganteng.tech/issue.net"
#wget -q -O /etc/issue.net "https://raw.githubusercontent.com/ALVIICELL/1/main/issue.net"
chmod +x /etc/issue.net
echo "Banner /etc/issue.net" >> /etc/ssh/sshd_config
sed -i 's@DROPBEAR_BANNER=""@DROPBEAR_BANNER="/etc/issue.net"@g' /etc/default/dropbear

wget https://gitlab.mzyaddy.ganteng.tech/bbr.sh && chmod +x bbr.sh && ./bbr.sh
#wget https://raw.githubusercontent.com/ALVIICELL/1/main/ssh/bbr.sh && chmod +x bbr.sh && ./bbr.sh

# blockir torrent
iptables -A FORWARD -m string --string "get_peers" --algo bm -j DROP
iptables -A FORWARD -m string --string "announce_peer" --algo bm -j DROP
iptables -A FORWARD -m string --string "find_node" --algo bm -j DROP
iptables -A FORWARD -m string --algo bm --string "BitTorrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "BitTorrent protocol" -j DROP
iptables -A FORWARD -m string --algo bm --string "peer_id=" -j DROP
iptables -A FORWARD -m string --algo bm --string ".torrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "announce.php?passkey=" -j DROP
iptables -A FORWARD -m string --algo bm --string "torrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "announce" -j DROP
iptables -A FORWARD -m string --algo bm --string "info_hash" -j DROP
iptables-save > /etc/iptables.up.rules
iptables-restore -t < /etc/iptables.up.rules
netfilter-persistent save
netfilter-persistent reload

wget -qO /usr/bin/clearlog "http://gitlab.mzyaddy.ganteng.tech/clearlog.sh"
chmod 777 /usr/bin/clearlog
echo "*/25 * * * * root clearlog" >> /etc/crontab

cat > /etc/cron.d/re_otm <<-END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
0 2 * * * root /sbin/reboot
END

cat > /etc/cron.d/xp_otm <<-END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
0 0 * * * root /usr/bin/xp
END

cat > /home/re_otm <<-END
7
END
function bersihbersih(){
source /etc/os-release
    if [ -f "/usr/bin/apt-get" ];then
            isDebian=`cat /etc/issue|grep Debian`
            if [ "$isDebian" != "" ];then
                    echo -e "[ ${green}INFO$NC ] Clearing trash"
                    apt autoclean -y >/dev/null 2>&1
                    if dpkg -s unscd >/dev/null 2>&1; then
                        apt -y remove --purge unscd >/dev/null 2>&1
                    fi
                    apt -y --purge remove samba* >/dev/null 2>&1
                    apt -y --purge remove apache2* >/dev/null 2>&1
                    apt -y --purge remove bind9* >/dev/null 2>&1
                    apt -y remove sendmail* >/dev/null 2>&1
                    apt autoremove -y >/dev/null 2>&1
            else
                    echo -e "[ ${green}INFO$NC ] Clearing trash"
                    apt-get autoclean -y >/dev/null 2>&1
                    if dpkg -s unscd >/dev/null 2>&1; then
                        apt-get -y remove --purge unscd >/dev/null 2>&1
                    fi
                    apt-get -y --purge remove samba* >/dev/null 2>&1
                    apt-get -y --purge remove apache2* >/dev/null 2>&1
                    apt-get -y --purge remove bind9* >/dev/null 2>&1
                    apt-get -y remove sendmail* >/dev/null 2>&1
                    apt-get autoremove -y >/dev/null 2>&1
            fi
    else
        echo "ini vps Centos"
        OS=centos
        echo -e "[ ${green}INFO$NC ] Clearing trash"
        yum autoclean -y >/dev/null 2>&1
        echo "ubah manual apt menjadi yum , contoh apt install squid menjadi yum install squid"
        echo "atau chat saya di telegram kalau kamu ga paham"
        echo "contact person t.me/Crystalllz"
        #exit
        sleep 3s
    fi
}
bersihbersih
sleep 1
# finishing
cd
chown -R www-data:www-data /home/vps/public_html
echo -e "$yell[SERVICE]$NC Restart All service SSH & OVPN"
sleep 1
echo -e "[ ${green}ok${NC} ] Restarting cron "
sleep 1
service cron restart >/dev/null 2>&1
service cron reload >/dev/null 2>&1
echo -e "[ ${green}ok${NC} ] Restarting nginx"
/etc/init.d/nginx restart >/dev/null 2>&1
echo -e "[ ${green}ok${NC} ] Restarting openvpn"
/etc/init.d/openvpn restart >/dev/null 2>&1
echo -e "[ ${green}ok${NC} ] Restarting ssh "
/etc/init.d/ssh restart >/dev/null 2>&1
echo -e "[ ${green}ok${NC} ] Restarting dropbear "
/etc/init.d/dropbear restart >/dev/null 2>&1
echo -e "[ ${green}ok${NC} ] Restarting fail2ban "
/etc/init.d/fail2ban restart >/dev/null 2>&1
echo -e "[ ${green}ok${NC} ] Restarting stunnel4 "
/etc/init.d/stunnel4 restart >/dev/null 2>&1
echo -e "[ ${green}ok${NC} ] Restarting vnstat "
/etc/init.d/vnstat restart >/dev/null 2>&1
echo -e "[ ${green}ok${NC} ] Restarting squid "
/etc/init.d/squid restart >/dev/null 2>&1
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7100 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7200 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7400 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7500 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7600 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7700 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7800 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7900 --max-clients 500
history -c
echo "unset HISTFILE" >> /etc/profile
clear

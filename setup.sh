#!/bin/bash
dateFromServer=$(curl -v --insecure --silent https://google.com/ 2>&1 | grep Date | sed -e 's/< Date: //')
biji=`date +"%Y-%m-%d" -d "$dateFromServer"`
clear
red='\e[1;31m'
green='\e[0;32m'
yell='\e[1;33m'
tyblue='\e[1;36m'
NC='\e[0m'
yellow() { echo -e "\\033[33;1m${*}\\033[0m"; }
cd /root
function secs_to_human() {
    echo "Installation time : $(( ${1} / 3600 )) hours $(( (${1} / 60) % 60 )) minute's $(( ${1} % 60 )) seconds"
}
start=$(date +%s)
function skriputama(){
wget https://raw.githubusercontent.com/baconfig/ahmadtnl/main/tools.sh && chmod +x tools.sh && ./tools.sh && clear
wget https://raw.githubusercontent.com/baconfig/ahmadtnl/main/domaincf.sh && chmod +x domaincf.sh && ./domaincf.sh && clear
wget https://raw.githubusercontent.com/baconfig/ahmadtnl/main/ssh-vpn.sh && chmod +x ssh-vpn.sh && ./ssh-vpn.sh && clear
wget https://raw.githubusercontent.com/baconfig/ahmadtnl/main/ins-xray.sh && chmod +x ins-xray.sh && ./ins-xray.sh && clear
wget http://gitlab.mzyaddy.ganteng.tech/insshws.sh && chmod +x insshws.sh && ./insshws.sh && clear
#wget https://install.yudhy.net/WEBSOCKET/insshws.sh && chmod +x insshws.sh && ./insshws.sh && clear
wget https://gitlab.mzyaddy.ganteng.tech/updatesshws.sh && chmod +x updatesshws.sh && ./updatesshws.sh && clear
wget https://raw.githubusercontent.com/baconfig/ahmadtnl/main/ohp.sh && chmod +x ohp.sh && ./ohp.sh && clear
wget https://raw.githubusercontent.com/baconfig/ahmadtnl/main/slowdns.sh && chmod +x slowdns.sh && ./slowdns.sh && clear
wget https://raw.githubusercontent.com/baconfig/ahmadtnl/main/set-br.sh && chmod +x set-br.sh && ./set-br.sh && clear
sleep 3
clear
wget https://install.yudhy.net/MENU/update.sh && chmod +x update.sh && ./update.sh
clear
rm -fr /root/backupmenu >/dev/null 2>&1
mkdir -p /root/backupmenu
cp -f /usr/bin/menu /root/backupmenu
cp -f /usr/bin/menu-ssh /root/backupmenu
cp -f /usr/bin/menu-vmess /root/backupmenu
cp -f /usr/bin/menu-vless /root/backupmenu
cp -f /usr/bin/menu-ss /root/backupmenu

mv -f /usr/bin/menu-trojan /root/backupmenu >/dev/null 2>&1
mv -f /usr/bin/menu /root/backupmenu >/dev/null 2>&1

wget -q -O /usr/bin/menu "http://gitlab.mzyaddy.ganteng.tech/fix/menu.sh" && chmod +x /usr/bin/menu
wget -q -O /usr/bin/menu-trojan "http://gitlab.mzyaddy.ganteng.tech/fix/menu-trojan.sh" && chmod +x /usr/bin/menu-trojan

sed -i "s/yudhynetwork-pro/yaddykakkoii-pro/g" /usr/bin/menu-trojan
sed -i "s/yudhynetwork/yaddykakkoii/g" /usr/bin/menu-trojan
sed -i "s/yudhynet/yaddyganteng/g" /usr/bin/menu-trojan
}
skriputama

cat> /root/.profile << END
# ~/.profile: executed by Bourne-compatible login shells.

if [ "$BASH" ]; then
  if [ -f ~/.bashrc ]; then
    . ~/.bashrc
  fi
fi

mesg n || true
clear
menu
END
chmod 644 /root/.profile
    if [ -f "/root/log-install.txt" ]; then
        rm /root/log-install.txt > /dev/null 2>&1
    fi
    if [ -f "/etc/afak.conf" ]; then
        rm /etc/afak.conf > /dev/null 2>&1
    fi
    if [ ! -f "/etc/log-create-user.log" ]; then
        echo "Log All Account " > /etc/log-create-user.log
    fi
history -c
#serverV=$( curl -sS https://install.yudhy.net/version  )
serverV=1.1
echo $serverV > /opt/.ver
aureb=$(cat /home/re_otm)
b=11
if [ $aureb -gt $b ]
then
gg="PM"
else
gg="AM"
fi
curl -sS ifconfig.me > /etc/myipvps
echo " "
echo "Installation has been completed!!"
echo " "
echo ""
echo "------------------------------------------------------------"
echo ""
echo ""
echo "=========================[SCRIPT PREMIUM LIFETIME]========================"
echo "=====================-[ SCRIPT RECODE BY AHMADSTORE ]-===================="
echo "   >>> Service & Port"  | tee -a log-install.txt
echo "   - OpenSSH		: 22"  | tee -a log-install.txt
echo "   - SSH UDP                : 1-65535"  | tee -a log-install.txt
echo "   - SSH Websocket	: 80 [ON]" | tee -a log-install.txt
echo "   - SSH SSL Websocket	: 443" | tee -a log-install.txt
echo "   - Stunnel4		: 447, 777" | tee -a log-install.txt
echo "   - Dropbear		: 109, 143" | tee -a log-install.txt
echo "   - Badvpn		: 7100-7900" | tee -a log-install.txt
echo "   - Nginx		: 81" | tee -a log-install.txt
echo "   - Vmess TLS		: 443" | tee -a log-install.txt
echo "   - Vmess None TLS	: 80" | tee -a log-install.txt
echo "   - Vless TLS		: 443" | tee -a log-install.txt
echo "   - Vless None TLS	: 80" | tee -a log-install.txt
echo "   - Trojan GRPC		: 443" | tee -a log-install.txt
echo "   - Trojan WS		: 443" | tee -a log-install.txt
echo "   - Trojan Go		: 443" | tee -a log-install.txt
echo "   - slowdns              : 443,80,8080,53,5300" | tee -a log-install.txt
echo "    [INFORMASI Shadowsocks-R & Shadowsocks]"  | tee -a log-install.txt
echo "    ---------------------------------------" | tee -a log-install.txt
echo "   - Websocket Shadowsocks   : 443"  | tee -a log-install.txt
echo "   - Shadowsocks GRPC        : 443"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "    [INFORMASI XRAY]"  | tee -a log-install.txt
echo "    ----------------" | tee -a log-install.txt
echo "   - Xray Vmess Ws Tls       : 443"  | tee -a log-install.txt
echo "   - Xray Vless Ws Tls       : 443"  | tee -a log-install.txt
echo "   - Xray Vmess Ws None Tls  : 80"  | tee -a log-install.txt
echo "   - Xray Vless Ws None Tls  : 80"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "    [INFORMASI TROJAN]"  | tee -a log-install.txt
echo "    ------------------" | tee -a log-install.txt
echo "   - Websocket Trojan        : 443"  | tee -a log-install.txt
echo "   - Trojan GRPC             : 443"  | tee -a log-install.txt
echo "   --------------------------------------------------------------" | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "   >>> Server Information & Other Features"  | tee -a log-install.txt
echo "   - Timezone		: Asia/Jakarta (GMT +7)"  | tee -a log-install.txt
echo "   - Fail2Ban		: [ON]"  | tee -a log-install.txt
echo "   - Dflate		: [ON]"  | tee -a log-install.txt
echo "   - IPtables		: [ON]"  | tee -a log-install.txt
echo "   - Auto-Reboot		: [ON]"  | tee -a log-install.txt
echo "   - IPv6			: [OFF]"  | tee -a log-install.txt
echo "   - Autoreboot On	: $aureb:00 $gg GMT +7" | tee -a log-install.txt

echo "   - Custom Path " | tee -a log-install.txt
echo "   - UDP ON" | tee -a log-install.txt
echo "   - Auto Backup Data" | tee -a log-install.txt

echo "   - AutoKill Multi Login User" | tee -a log-install.txt
echo "   - Auto Delete Expired Account" | tee -a log-install.txt
echo "   - Fully automatic script" | tee -a log-install.txt
echo "   - VPS settings" | tee -a log-install.txt
echo "   - Admin Control" | tee -a log-install.txt
echo "   - Change port" | tee -a log-install.txt
echo "   - Full Orders For Various Services" | tee -a log-install.txt
echo ""
echo ""
echo "------------------------------------------------------------"
echo ""
echo "===============-[ Script RECODE By MAGELANG PHREAKER]-==============="
echo -e ""
echo ""
echo "" | tee -a log-install.txt
sed -i "s/yaddyganteng/trojan-ws/g" /usr/bin/menu-trojan
wget https://raw.githubusercontent.com/baconfig/ahmadtnl/main/installsshudplama.sh
chmod +x installsshudplama.sh && ./installsshudplama.sh 2200,7100,7200,7300,7400,7500,7600,7700,7800,7900,53,5300
echo "==========SCRIPT UDP SUKSES TERINSTAL==========="
secs_to_human "$(($(date +%s) - ${start}))" | tee -a log-install.txt
echo -e "
"
read -n 1 -s -r -p "Press any key to reboot"
echo -e "    ${tyblue}.------------------------------------------.${NC}"
echo -e "    ${tyblue}|     SUCCESFULLY INSTALLED THE SCRIPT     |${NC}"
echo -e "    ${tyblue}'------------------------------------------'${NC}"
echo ""
sleep 3
echo -e "   ${tyblue}Your VPS Will Be Automatical Reboot In 10 seconds${NC}"
rm -f /root/key.pem
rm -f /root/cert.pem
rm -f /root/ssh-vpn.sh
rm -f /root/bbr.sh
rm /root/ins-xray.sh >/dev/null 2>&1
rm /root/insshws.sh >/dev/null 2>&1
rm /root/domaincf.sh >/dev/null 2>&1
rm -f installsshudplama.sh > /dev/null 2>&1
rm -f ins-xray.sh
rm -f ohp.sh
rm /root/update.sh
rm /root/setup.sh >/dev/null 2>&1
wget "http://gitlab.mzyaddy.ganteng.tech/fix/nginxfix.sh" && chmod 777 nginxfix.sh;./nginxfix.sh
sleep 10
reboot

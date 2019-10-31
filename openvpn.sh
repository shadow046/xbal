#!/bin/bash
apt update && cd ~/ && apt-get -y install git && git clone https://github.com/shadow046/openvpndeb.git && cd openvpndeb && chmod +x openvps
clear
	echo ""
	echo 'What do you want to do Pretty Boy?'
	echo "   1) Install VPS"
	echo "   2) Install OCS --Thanks to Bon-Chan--"
	echo "   3) Install OpenVPN Monitoring"
	echo "   4) All in One Installer"
	until [[ "$PORT_CHOICE" =~ ^[1-4]$ ]]; do
		read -rp "Choice [1-4]: " -e -i 1 PORT_CHOICE
	done
	case $PORT_CHOICE in
		1)
			#PORT="465"
			chmod +x vps && ./vps
		;;
		2)
			chmod +x ocs && ./ocs
		;;
		3)
			chmod +x monitor && ./monitor
		;;
		4)
			chmod +x openvps && ./openvps
		;;
	esac

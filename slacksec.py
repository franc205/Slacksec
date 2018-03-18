#!/usr/bin/python

import os, subprocess
import sys, traceback
import struct, time

#---------------------------------------------------------Installation Functions---------------------------------------------------------#

def intallAll():
	cmd = os.system("apt-get install -y wget git curl")
	cmd = os.system("apt-get install -y gqrx-sdr aircrack-ng sqlmap arduino wireshark sslstrip nmap hping3 amap-align kismet reaver cutycapt binwalk john proxychains apktool nikto ettercap-graphical etherape netdiscover driftnet netcat bkhive ophcrack hydra dsniff wifite foremost galleta guymager p0f volatility funkload slowhttptest sslsplit btscanner wifite samdump2 macchanger")
	armitage()
	beef()
	bluelog()
	bluemaho()
	bluepot()
	blueranger()
	burpsuite()
	casefile()
	gqrx()
	dirbuster()
	evilgrade()
	exploitdb()
	faraday()
	fern()
	fierce()
	findmyhash()
	hashcat()
	libnfc()
	maltego()
	metasploit()
	mfcuk()
	mfdread()
	mfok()
	pixieWPS()
	reconNG()
	setoolkit()
	theharvester()
	webshells()
	websploit()
	wifihoney()
	wpscan()
	time.sleep(2)

def armitage():
	cmd = os.system("apt-get install -y wget")
	cmd = os.system("wget \"http://www.fastandeasyhacking.com/download/armitage150813.tgz\" -O Armitage.tgz")
	cmd = os.system("tar -xvzf Armitage.tgz")
	cmd = os.system("sudo mv armitage /opt/metasploit")
	cmd = os.system("sudo chmod +x /opt/metasploit/armitage")
	cmd = os.system("rm -rf Armitage.tgz")
	armitage = open("/usr/bin/armitage", "a+")
	armitage.write("java -XX:+AggressiveHeap -XX:+UseParallelGC -jar /opt/metasploit/armitage.jar $@")	
	armitage.close()
	cmd = os.system("chmod +x /usr/bin/armitage")
	time.sleep(2)

def beef():
	#Install Requeriments
	cmd = os.system("apt-get install curl git build-essential openssl libreadline6 libreadline6-dev zlib1g zlib1g-dev libssl-dev libyaml-dev libsqlite3-0 libsqlite3-dev sqlite3 libxml2-dev libxslt1-dev autoconf libc6-dev libncurses5-dev automake libtool bison subversion")
	cmd = os.system("bash < <(curl -sk https://raw.github.com/wayneeseguin/rvm/master/binscripts/rvm-installer)")
	cmd = os.system("echo '[[ -s \"$HOME/.rvm/scripts/rvm\" ]] && . \"$HOME/.rvm/scripts/rvm\"' >> ~/.bashrc")
	cmd = os.system("source ~/.bashrc")
	cmd = os.system("source $HOME/.rvm/scripts/rvm")
	cmd = os.system("rvm install 1.9.2")
	cmd = os.system("rvm use 1.9.2 --default")
	#Install BeEF
	cmd = os.system("git clone git://github.com/beefproject/beef.git /usr/share/beef")
	cmd = os.system("cd /usr/share/beef && gem install bundler")
	cmd = os.system("cd /usr/share/beef && bundle install")
	#beef = open("/usr/bin/beef", "a+")
	#beef.write("cd /usr/share/beef/ && ./beef")
	#beef.close()
	#cmd = os.system("chmod +x /usr/bin/beef")
	print "Beef-XSS has been successfully installed on /usr/share/beef"
	time.sleep(2)

def bluelog():
	cmd = os.system("apt-get install -y git libbluetooth-dev")
	cmd = os.system("git clone https://github.com/MS3FGX/Bluelog.git /usr/share/bluelog")
	cmd = os.system("make -C /usr/share/bluelog")
	cmd = os.system("ln -s /usr/share/bluelog/bluelog /usr/bin/bluelog")
	time.sleep(2)
	
def bluemaho():
	cmd = os.system("apt-get install -y git")
	cmd = os.system("git clone git://git.kali.org/packages/bluemaho.git /usr/share/bluemaho")
	print "Bluemaho has been successfully installed on /usr/share/bluemaho"
	time.sleep(2)
	
def bluepot():
	cmd = os.system("apt-get install -y git")
	cmd = os.system("git clone git://git.kali.org/packages/bluepot.git /usr/share/bluepot")
	bpot = open("/usr/bin/bluepot", "a+")
	bpot.write("sudo java -jar /usr/share/bluepot/bluepot.jar")
	bpot.close()
	cmd = os.system("chmod +x /usr/bin/bluepot")
	time.sleep(2)

def blueranger():
	cmd = os.system("apt-get install -y git")
	cmd = os.system("git clone git://git.kali.org/packages/blueranger.git /usr/share/blueranger")
	cmd = os.system("chmod +x /usr/share/blueranger/blueranger.sh")
	cmd = os.system("ln -s /usr/share/blueranger/blueranger.sh /usr/bin/blueranger")
	time.sleep(2)
	
def burpsuite():
	cmd = os.system("apt-get install -y curl")
	cmd = os.system("curl https://portswigger.net/DownloadUpdate.ashx?Product=Free -o burpsuite_free.jar")
	cmd = os.system("mkdir /usr/share/burpsuite && mv burpsuite_free.jar /usr/share/burpsuite")
	burp = open("/usr/bin/burpsuite", "a+")
	burp.write("java -jar -Xmx1024m /usr/share/burpsuite/burpsuite_free.jar")
	burp.close()
	cmd = os.system("chmod +x /usr/bin/burpsuite")
	time.sleep(2)

def casefile():
	cmd = os.system("apt-get install -y wget")
	cmd = os.system("wget \"https://www.paterva.com/malv41/maltego_v4.1.0.10552.deb\" -O Casefile.deb")
	cmd = os.system("dpkg -i Casefile.deb")
	cmd = os.system("rm -rf Casefile.deb")
	time.sleep(2)

def gqrx():
	 cmd = os.system("sudo apt-get install gqrx-sdr")
	 time.sleep(2)

def dirbuster():
	cmd = os.system("apt-get install -y wget")
	cmd = os.system("wget \"http://downloads.sourceforge.net/project/dirbuster/DirBuster%20%28jar%20%2B%20lists%29/1.0-RC1/DirBuster-1.0-RC1.tar.bz2?r=http%3A%2F%2Fsourceforge.net%2Fprojects%2Fdirbuster%2Ffiles%2FDirBuster%2520%2528jar%2520%252B%2520lists%2529%2F1.0-RC1%2F&ts=1370262745&use_mirror=nchc\" -O DirBuster.tar.bz2")
	cmd = os.system("tar -xjvf DirBuster.tar.bz2")
	cmd = os.system("mv DirBuster-1.0-RC1 /usr/share/dirbuster")
	cmd = os.system("rm DirBuster.tar.bz2")
	dirbust = open("/usr/bin/dirbuster", "a+")
	dirbust.write("java -Xmx256M -jar /usr/share/dirbuster/DirBuster-1.0-RC1.jar")
	dirbust.close()
	cmd = os.system("chmod +x /usr/bin/dirbuster")
	time.sleep(2)

def evilgrade():
	print "Lo siento evilgrade esta pasado de moda"
	'''cmd = os.system("apt-get install -y git librpc-xml-perl libdata-dump-perl")
	cmd = os.system("git clone https://github.com/infobyte/evilgrade /usr/share/evilgrade")
	cmd = os.system("chmod +x /usr/share/evilgrade/evilgrade")
	dirbust = open("/usr/bin/evilgrade", "a+")
	dirbust.write("cd /usr/share/evilgrade/ && ./evilgrade")
	dirbust.close()
	cmd = os.system("chmod +x /usr/bin/evilgrade")
	time.sleep(2)'''

def exploitdb():
	cmd = os.system("apt-get install -y git")
	cmd = os.system("git clone git://git.kali.org/packages/exploitdb.git /usr/share/exploitdb")
	cmd = os.system("ln -s /usr/share/exploitdb/searchsploit /usr/bin/searchsploit")
	time.sleep(2)

def faraday ():
	cmd = os.system("apt-get install -y git python-pip curl sudo")
	cmd = os.system("git clone https://github.com/infobyte/faraday.git /usr/share/python-faraday")
	cmd = os.system("chmod +x /usr/share/python-faraday/install.sh")
	cmd = os.system("cd /usr/share/python-faraday && ./install.sh")
	cmd = os.system("easy_install -U setuptools")
	cmd = os.system("chmod +x /usr/bin/python-faraday")
	#user = os.system("who -H | sed \'1d\' | cut -d \" \" -f 1")
	user = subprocess.check_output("who -H | sed \'1d\' | cut -d \" \" -f 1", shell=True) #Obtiene el nombre de Usuario que se logueo
	user = user.replace('\n', '').replace('\r', '')
	cmd = os.system("mv/home/%s/faraday/python-faraday /usr/bin/python-faraday" % user)
	cmd = os.system("mv /home/%s/faraday/python-faraday.service /lib/systemd/system/python-faraday.service" % user)
	cmd = os.system("mv /home/%s/faraday/install.sh /usr/share/python-faraday" % user)
	time.sleep(2)

def fern():
	cmd = os.system("apt-get install -y python-qt4 macchanger xterm aircrack-ng subversion python-scapy")
	cmd = os.system("git clone https://github.com/savio-code/fern-wifi-cracker.git /usr/share/Fern-wifi-cracker")
	cmd = os.system("cd /usr/share/Fern-wifi-cracker/Fern-Wifi-Cracker")
	cmd = os.system("mv /usr/share/Fern-wifi-cracker/Fern-Wifi-Cracker /usr/share/fern-wifi-cracker/")
	cmd = os.system("rm -rf /usr/share/Fern-wifi-cracker")
	time.sleep(2)

def fierce():
	cmd = os.system("apt-get install -y git python3-pip")
	cmd = os.system("sudo cpan -i Net::DNS")
	cmd = os.system("git clone  \"https://github.com/davidpepper/fierce-domain-scanner.git\" /usr/share/fierce")
	cmd = os.system("sudo chmod +x /usr/share/fierce/fierce.pl")
	cmd = os.system("sudo mv /usr/share/fierce/fierce.pl /usr/bin/fierce")
	time.sleep(2)


def findmyhash():
	cmd = os.system("apt-get install -y wget")
	cmd = os.system("wget \"http://findmyhash.googlecode.com/files/findmyhash.py\" -O findmyhash.py")
	cmd = os.system("mkdir /usr/share/findmyhash")
	cmd = os.system("mv findmyhash.py /usr/share/findmyhash/findmyhash.py")
	findhash = open("/usr/bin/findmyhash", "a+")
	findhash.write("python /usr/share/findmyhash/findmyhash.py")
	findhash.close()
	cmd = os.system("chmod +x /usr/bin/findmyhash")
	time.sleep(2)

def hashcat():
	cmd = os.system("apt-get install wget p7zip-full")
	cmd = os.system("wget \"https://hashcat.net/files/hashcat-4.1.0.7z\" -O Hashcat.7z")
	cmd = os.system("7za x Hashcat.7z")
	cmd = os.system("mv hashcat-3.00 /usr/share/hashcat")
	cmd = os.system("rm -rf hashcat-3.00")
	cmd = os.system("rm -rf Hashcat.7z")
	if struct.calcsize("P") * 8 == 64:
		cmd = os.system("ln -s /usr/share/hashcat/hashcat64.bin /usr/bin/hashcat")
		time.sleep(2)
	elif struct.calcsize("P") * 8 == 32:
		cmd = os.system("ln -s /usr/share/hashcat/hashcat32.bin /usr/bin/hashcat")
		time.sleep(2)
	else:
		print "Hashcat successfully installed in /usr/share/hashcat"
		time.sleep(2)

def libnfc():
	cmd = os.system("apt-get install git libusb-dev dh-autoreconf autoconf automake libtool pkg-config")
	cmd = os.system("git clone https://github.com/nfc-tools/libnfc.git /usr/share/nfctools/libnfc")
	cmd = os.system("cd /usr/share/nfctools/libnfc && git checkout libnfc-1.7.1")
	cmd = os.system("cd /usr/share/nfctools/libnfc && git clean -d -f -x")
	cmd = os.system("cd /usr/share/nfctools/libnfc && git remote|grep -q anonscm||git remote add anonscm git://anonscm.debian.org/collab-maint/libnfc.git")
	cmd = os.system("cd /usr/share/nfctools/libnfc && git fetch anonscm")
	cmd = os.system("cd /usr/share/nfctools/libnfc && git checkout remotes/anonscm/master debian")
	cmd = os.system("cd /usr/share/nfctools/libnfc && git reset")
	cmd = os.system("cd /usr/share/nfctools/libnfc && dpkg-buildpackage -uc -us -b")
	cmd = os.system("cd /usr/share/nfctools/libnfc && apt-get install libusb-0.1-4")
	cmd = os.system("cd /usr/share/nfctools/libnfc && dpkg -i ../libnfc*.deb")
	time.sleep(2)

def libfreefare():
	cmd = os.system("apt-get install git libusb-dev dh-autoreconf autoconf automake libtool libssl-dev pkg-config")
	cmd = os.system("git clone https://github.com/nfc-tools/libfreefare.git /usr/share/nfctools/libfreefare")
	cmd = os.system("cd /usr/share/nfctools/libfreefare && autoreconf -vis")
	cmd = os.system("cd /usr/share/nfctools/libfreefare && ./configure --prefix=/usr")
	cmd = os.system("cd /usr/share/nfctools/libfreefare && make && make install")
	time.sleep(2)
	
def maltego():
	cmd = os.system("apt-get install -y wget")
	cmd = os.system("wget \"https://www.paterva.com/malv41/maltego_v4.1.0.10552.deb\" -O Maltego.deb")
	cmd = os.system("dpkg -i Maltego.deb")
	cmd = os.system("rm -rf Maltego.deb")
	time.sleep(2)
	
def metasploit():
	cmd = os.system("apt-get install curl")
	cmd = os.system("curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall")
	cmd = os.system("chmod 755 msfinstall")
	cmd = os.system("./msfinstall")
	cmd = os.system("rm -rf msfinstall")
	armitageChoice = raw_input("Do you want to install Armitage? [Y/n] ")
	if armitageChoice == "Y" or armitageChoice == "y":
		armitage()
	else:
		time.sleep(2)
		main()

def metasploitOLD():
	cmd = os.system("sudo apt-get install -y nmap build-essential libreadline-dev  libssl-dev libpq5 libpq-dev libreadline5 libsqlite3-dev libpcap-dev openjdk-8-jre subversion git-core autoconf postgresql pgadmin3 curl zlib1g-dev libxml2-dev libxslt1-dev libyaml-dev curl ruby nmap")
	print '\033[91m' + "Please write 'msf' as Password" + '\033[0m'
	cmd = os.system("cd / && su postgres -c 'createuser msf -P -S -R -D'")
	cmd = os.system("cd / && su postgres -c 'createdb -O msf msf'")
	cmd = os.system("git clone https://github.com/rapid7/metasploit-framework /opt/metasploit-framework")
	cmd = os.system("sudo chown -R `whoami` /opt/metasploit-framework")
	cmd = os.system("cd /opt/metasploit-framework && gem install bundler")
	cmd = os.system("cd /opt/metasploit-framework && bundle install")
	cmd = os.system("cd /opt/metasploit-framework && sudo bash -c 'for MSF in $(ls msf*); do ln -s /opt/metasploit-framework/$MSF /usr/local/bin/$MSF;done'")
	msf = open("/opt/metasploit-framework/config/database.yml", "w+")
	msf.write('''production:
 adapter: postgresql
 database: msf
 username: msf
 password: msf
 host: 127.0.0.1
 port: 5432
 pool: 75
 timeout: 5''')
	msf.close()
	cmd = os.system("sudo sh -c \"echo export MSF_DATABASE_CONFIG=/opt/metasploit-framework/config/database.yml >> /etc/profile\"")
	cmd = os.system("source /etc/profile")
	armitageChoice = raw_input("Do you want to install Armitage? [Y/n] ")
	if armitageChoice == "Y" or armitageChoice == "y":
		armitage()
	else:
		time.sleep(2)
		main()

def mfok():
	cmd = os.system("apt-get install -y git libusb-dev dh-autoreconf autoconf automake libtool pkg-confi")
	cmd = os.system("git clone https://github.com/nfc-tools/mfoc.git /usr/share/nfctools/mfok")
	cmd = os.system("cd /usr/share/nfctools/mfok && autoreconf -vis")
	cmd = os.system("cd /usr/share/nfctools/mfok && ./configure")
	cmd = os.system("cd /usr/share/nfctools/mfok/src && make && make install")
	time.sleep(2)

def mfdread():
	cmd = os.system("apt-get install -y git python-pip")
	cmd = os.system("git clone https://github.com/zhovner/mfdread.git /usr/share/nfctools/mfdread")
	cmd = os.system("ln -s /usr/share/nfctools/mfdread/mfdread.py /usr/bin/mfdread")

def mfcuk():
	cmd = os.system("apt-get install -y git libusb-dev dh-autoreconf autoconf automake libtool pkg-confi")
	cmd = os.system("git clone https://github.com/nfc-tools/mfcuk.git /usr/share/nfctools/mfcuk")
	cmd = os.system("cd /usr/share/nfctools/mfcuk && autoreconf -is")
	cmd = os.system("cd /usr/share/nfctools/mfcuk && ./configure")
	cmd = os.system("cd /usr/share/nfctools/mfcuk/src && make && make install")
	time.sleep(2)

def owaspZAP():
	cmd = os.system("apt-get install -y wget")
	cmd = os.system("wget \"https://github.com/zaproxy/zaproxy/releases/download/2.7.0/ZAP_2.7.0_Linux.tar.gz\" -O OWASP_ZAP.tar.gz")
	cmd = os.system("tar -xvzf OWASP_ZAP.tar.gz")
	cmd = os.system("mv ZAP_2.5.0 /usr/share/owasp-zap")
	cmd = os.system("rm -rf OWASP_ZAP.tar.gz")
	cmd = os.system("ln -s /usr/share/owasp-zap/zap.sh /usr/bin/owasp-zap")
	time.sleep(2)
	
def pixieWPS():
	cmd = os.system("apt-get install -y git build-essential libpcap-dev sqlite3 libsqlite3-dev libssl-dev unzip")
	cmd = os.system("git clone https://github.com/wiire/pixiewps /tmp/pixiewps")
	cmd = os.system("make -C /tmp/pixiewps/src")
	cmd = os.system("make install -C /tmp/pixiewps/src")
	cmd = os.system("rm -rf /tmp/pixiewps")
	time.sleep(2)

def reconNG():
	cmd = os.system("apt-get install -y git")
	cmd = os.system("git clone https://LaNMaSteR53@bitbucket.org/LaNMaSteR53/recon-ng.git /usr/share/recon-ng")
	cmd = os.system("ln -s /usr/share/recon-ng/recon-ng /usr/bin/recon-ng")
	time.sleep(2)
	
def setoolkit():
	cmd = os.system("apt-get install -y git")
	cmd = os.system("git clone https://github.com/trustedsec/social-engineer-toolkit/ /usr/share/set")
	cmd = os.system("ln -s /usr/share/set/setoolkit /usr/bin/setoolkit")
	time.sleep(2)

def theharvester():
	cmd = os.system("apt-get install -y git python-pip python-dev build-essential")
	cmd = os.system("pip install requests")
	cmd = os.system("git clone https://github.com/laramies/theHarvester /usr/share/theharvester")
	cmd = os.system("ln -s /usr/share/theharvester/theHarvester.py /usr/bin/theHarvester")
	cmd = os.system("chmod +x /usr/bin/theHarvester")
	time.sleep(2)

def vega():
	cmd = os.system("apt-get install -y wget unzip libwebkitgtk-1.0")
	if struct.calcsize("P") * 8 == 64:
		cmd = os.system("wget \"https://dist.subgraph.com/downloads/VegaBuild-linux.gtk.x86_64.zip\" -O Vega.x64.zip")
		cmd = os.system("unzip Vega.x64.zip")
		cmd = os.system("mv vega /usr/share/vega")
		cmd = os.system("rm -rf Vega.x64.zip")
		cmd = os.system("ln -s /usr/share/vega/Vega /usr/bin/vega")
		time.sleep(2)
	elif struct.calcsize("P") * 8 == 32:
		cmd = os.system("wget \"https://dist.subgraph.com/downloads/VegaBuild-linux.gtk.x86.zip\" -O Vega.x86.zip")
		cmd = os.system("unzip Vega.x86.zip")
		cmd = os.system("mv vega /usr/share/vega")
		cmd = os.system("rm -rf Vega.x86.zip")
		cmd = os.system("ln -s /usr/share/vega/Vega /usr/bin/vega")
		time.sleep(2)
	else:
		print "There has been a problem installing Vega!"

def webshells():
	cmd = os.system("apt-get install -y git")
	cmd = os.system("git clone git://git.kali.org/packages/webshells.git /usr/share/webshells")
	time.sleep(2)
	
def websploit():
	cmd = os.system("apt-get install -y wget")
	cmd = os.system("wget \"http://downloads.sourceforge.net/project/websploit/WebSploit%20Framework%20V.3.0.0/WebSploit-Framework-3.0.0.tar.gz?r=https%3A%2F%2Fsourceforge.net%2Fprojects%2Fwebsploit%2F&ts=1467510406&use_mirror=tenet\" -O Websploit.tar.gz")
	cmd = os.system("tar -xf Websploit.tar.gz")
	cmd = os.system("mv websploit /tmp/websploit")
	cmd = os.system("rm -rf Websploit.tar.gz")
	cmd = os.system("cd /tmp/websploit && ./install.sh")	
	time.sleep(2)

def wifihoney():
	cmd = os.system("apt-get install -y git")
	cmd = os.system("git clone git://git.kali.org/packages/wifi-honey.git /usr/share/wifi-honey")
	cmd = os.system("ln -s /usr/share/wifi-honey/wifi_honey.sh /usr/bin/wifihoney")
	cmd = os.system("chmod +x /usr/share/wifi-honey/wifi_honey.sh")
	time.sleep(2)
	
def wpscan():
	cmd = os.system("sudo apt-get install -y git libcurl4-openssl-dev libxml2 libxml2-dev libxslt1-dev ruby-dev build-essential libgmp-dev")
	cmd = os.system("git clone https://github.com/wpscanteam/wpscan.git /usr/share/wpscan")
	cmd = os.system("cd /usr/share/wpscan && sudo gem install bundler")
	cmd = os.system("cd /usr/share/wpscan && bundle install --without test")
	cmd = os.system("ln -s \"/usr/share/wpscan/wpscan.rb\" /usr/bin/wpscan")
	cmd = os.system("chmod +x /usr/bin/wpscan")
	'''cmd = os.system("echo  '#!/bin/bash ' >>  /usr/bin/wpscan; echo 'cd /usr/share/wpscan/ && ./wpscan.rb \'$@\' >>  /usr/bin/wpscan '; ")'''
	#cmd = os.system("chmod +x /usr/bin/wpscan")
	#wpscan = open("/usr/bin/wpscan", "a+")
	#wpscan.write("cd /usr/share/wpscan/ && ls && echo \"Usage: ./wpscan.rb \"")
	#wpscan.close()
	#print "mv /home/user/wpscan/wpscan /usr/bin/wpscan"
	print "WPScan has been successfully installed on /usr/share/wpscan"
	time.sleep(2)


#--------------------------------------------------------------Menu Functions--------------------------------------------------------------#

def main():
	if os.geteuid() != 0:
		exit("You need to have root privileges to run this script.\nPlease try again, this time using 'sudo'. Exiting.")
	else:
		try:
			while True:
				print '''

	  #####                               #####                
	 #     # #        ##    ####  #    # #     # ######  ####  
	 #       #       #  #  #    # #   #  #       #      #    # 
	  #####  #      #    # #      ####    #####  #####  #      
	       # #      ###### #      #  #         # #      #      
	 #     # #      #    # #    # #   #  #     # #      #    # 
	  #####  ###### #    #  ####  #    #  #####  ######  ####  
							By Franc205

	----------------------------Choose a Category----------------------------
	1) Essential Tools				5) Exploitation Tools
	2) Wireless Tools				6) Password Attacks	
	3) Web Hacking Tools				7) Reporting Tools
	4) Sniffing & Spoofing				8) NFC Hacking Tools
	9) HELP!

	0) All the tools
				'''
				mainChoice = raw_input("Choose an option: ")
				if mainChoice == "0":
					allMenu()
				elif mainChoice == "1":
					essentialMenu()
				elif mainChoice == "2":
					wirelessMenu()
				elif mainChoice == "3":
					webMenu()
				elif mainChoice == "4":
					sniffingMenu()
				elif mainChoice == "5":
					explotationMenu()
				elif mainChoice == "6":
					passwordMenu()
				elif mainChoice == "7":
					reportMenu()
				elif mainChoice == "8":
					nfcMenu()
				elif mainChoice == "9":
					HELP()
				elif mainChoice == "home":
					print "You are already at Home!!!"
				else:
					print "Please choose a valid option!!!"
					time.sleep(2)
		except KeyboardInterrupt:
			print "See You!!!"
		except Exception:
			traceback.print_exc(file=sys.stdout)
		sys.exit(0)

def allMenu():
		print'''
-------------------------------------------All The Tools-------------------------------------------

1) Aircrack-ng				23) Evilgrade				     	45) PixieWPS
2) Amap					24) ExploitDB				        46) Proxychains
3) Apktool				25) Faraday				        47) P0F
4) Arduino				26) Findmyhash			                48) Reaver
5) BTScanner				27) Foremost	                                49) Recon-ng
6) BeEF					28) Funkload		                        50) SET
7) Binwalk				29) Galleta			                51) SQLMap
8) Bkhive				30) Guymager		                        52) SSLSplit
9) Bluelog				31) Hashcat		                        53) SSLstrip
10) Bluemaho				32) Hping3	                                54) Samdump2
11) Bluepot				33) Hydra		                        55) SlowHTTPTest
12) Blueranger				34) John the ripper				56) TheHarvester
13) Bluesnarfer				35) Kismet		                        57) Vega
14) BurpSuite				36) Macchanger					58) Volatility
15) Casefile				37) Maltego			                59) WPScaner
16) gqrx				38) Metaspoit + Armitage	                60) Webshells
17) CutyCapt				39) NMap				        61) Websploit
18) Dirbuster				40) Netcat		                        62) Wifi Honey
19) Driftnet				41) Netdiscover				        63) Wifite
20) Dsniff				42) Nikto	                                64) Wireshark
21) Etherape				43) OWASP ZAP					65) NFC Tools
22) Ettercap				44) Ophcrack				        66) Fierce

0) Install All
'''
		mainChoice = raw_input("Choose an option: ")
		if mainChoice == "back":
			main()
		elif mainChoice == "home":
			main()
		elif mainChoice == "help":
			HELP()
		elif mainChoice == "0":
			intallAll()
		elif mainChoice == "1":
			cmd = os.system("apt-get install -y aircrack-ng")
			time.sleep(2)
		elif mainChoice == "2":
			cmd = os.system("apt-get install -y amap-align")
			time.sleep(2)
		elif mainChoice == "3":
			cmd = os.system("apt-get install -y apktool")
			time.sleep(2)
		elif mainChoice == "4":
			cmd = os.system("apt-get install -y arduino")
			time.sleep(2)
		elif mainChoice == "5":
			print "Comming Soon!"
			#btscanner()
		elif mainChoice == "6":
			beef()
		elif mainChoice == "7":
			cmd = os.system("apt-get install -y binwalk")
			time.sleep(2)
		elif mainChoice == "8":
			cmd = os.system("apt-get install -y bkhive")
			time.sleep(2)
		elif mainChoice == "9":
			bluelog()
		elif mainChoice == "10":
			bluemaho()
		elif mainChoice == "11":
			bluepot()
		elif mainChoice == "12":
			blueranger()
		elif mainChoice == "13":
			print "Coming Soon!"
			#bluesnarfer()
		elif mainChoice == "14":
			burpsuite()
		elif mainChoice == "15":
			casefile()
		elif mainChoice == "16":
			gqrx()
		elif mainChoice == "17":
			cmd = os.system("apt-get install -y cutycapt")
			time.sleep(2)
		elif mainChoice == "18":
			dirbuster()
		elif mainChoice == "19":
			cmd = os.system("apt-get install -y driftnet")
			time.sleep(2)
		elif mainChoice == "20":
			cmd = os.system("apt-get install -y dsniff")
			time.sleep(2)
		elif mainChoice == "21":
			cmd = os.system("apt-get install -y etherape")
			time.sleep(2)
		elif mainChoice == "22":
			cmd = os.system("apt-get install -y ettercap-graphical")
			time.sleep(2)
		elif mainChoice == "23":
			evilgrade()
		elif mainChoice == "24":
			exploitdb()
		elif mainChoice == "25":
			faraday()
		elif mainChoice == "26":
			findmyhash()	
		elif mainChoice == "27":
			cmd = os.system("apt-get install -y foremost")
			time.sleep(2)
		elif mainChoice == "28":
			cmd = os.system("apt-get install -y funkload")
			time.sleep(2)
		elif mainChoice == "29":
			cmd = os.system("apt-get install -y galleta")
			time.sleep(2)
		elif mainChoice == "30":
			cmd = os.system("apt-get install -y guymager")
			time.sleep(2)
		elif mainChoice == "31":
			hashcat()
		elif mainChoice == "32":
			cmd = os.system("apt-get install -y hping3")
			time.sleep(2)
		elif mainChoice == "33":
			cmd = os.system("apt-get install -y hydra")
			time.sleep(2)
		elif mainChoice == "34":
			cmd = os.system("apt-get install -y john")
			time.sleep(2)
		elif mainChoice == "35":
			cmd = os.system("apt-get install -y kismet")
			time.sleep(2)
		elif mainChoice == "36":
			cmd = os.system("apt-get install -y macchanger")
			time.sleep(2)
		elif mainChoice == "37":
			maltego()
		elif mainChoice == "38":
			metasploit()
		elif mainChoice == "39":
			cmd = os.system("apt-get install -y nmap")
			time.sleep(2)
		elif mainChoice == "40":
			cmd = os.system("apt-get install -y netcat")
			time.sleep(2)
		elif mainChoice == "41":
			cmd = os.system("apt-get install -y netdiscover")
			time.sleep(2)
		elif mainChoice == "42":
			cmd = os.system("apt-get install -y nikto")
			time.sleep(2)
		elif mainChoice == "43":
			owaspZAP()
		elif mainChoice == "44":
			cmd = os.system("apt-get install -y ophcrack")
			time.sleep(2)
		elif mainChoice == "45":
			pixieWPS()
		elif mainChoice == "46":
			cmd = os.system("apt-get install -y proxychains")
			time.sleep(2)
		elif mainChoice == "47":
			cmd = os.system("apt-get install -y p0f")
			time.sleep(2)
		elif mainChoice == "48":
			cmd = os.system("apt-get install -y reaver")
			time.sleep(2)
		elif mainChoice == "49":
			cmd = os.system("apt-get install -y recon-ng")
			time.sleep(2)
		elif mainChoice == "50":
			setoolkit()
		elif mainChoice == "51":
			cmd = os.system("apt-get install -y sqlmap")
			time.sleep(2)
		elif mainChoice == "52":
			cmd = os.system("apt-get install -y sslsplit")
			time.sleep(2)
		elif mainChoice == "53":
			cmd = os.system("apt-get install -y sslstrip")
			time.sleep(2)
		elif mainChoice == "54":
			cmd = os.system("apt-get install -y samdump2")
			time.sleep(2)
		elif mainChoice == "55":
			cmd = os.system("apt-get install -y slowhttptest")
			time.sleep(2)
		elif mainChoice == "56":
			theharvester()
		elif mainChoice == "57":
			vega()
		elif mainChoice == "58":
			cmd = os.system("apt-get install -y volatility")
			time.sleep(2)
		elif mainChoice == "59":
			wpscan()
		elif mainChoice == "60":
			webshells()
		elif mainChoice == "61":
			websploit()
		elif mainChoice == "62":
			wifihoney()
		elif mainChoice == "63":
			cmd = os.system("apt-get install -y wifite")
			time.sleep(2)
		elif mainChoice == "64":
			cmd = os.system("apt-get install -y wireshark")
			time.sleep(2)
		elif mainChoice == "65":
			libnfc()
			mfcuk()
			mfok()
			libfreefare()
			mfdread()
			time.sleep(2)
		elif mainChoice == "66":
			fierce()
		else:
			print "Please choose a valid option!!!"
			time.sleep(2)

def essentialMenu():
	print'''
---------------------------Essential Tools---------------------------
1) Aircrack-NG						6) Netcat            
2) DSniff						7) Nmap
3) Faraday						8) OWASP Zap
4) Hping3						9) SET
5) Metasploit + Armitage					10) Wireshark

0) Install All
	'''

	mainChoice = raw_input("Choose an option: ")
	if mainChoice == "back":
		main()
	elif mainChoice == "home":
		main()
	elif mainChoice == "help":
		HELP()
	elif mainChoice == "0":
		cmd = os.system("apt-get install -y aircrack-ng dsniff hping3 netcat nmap wireshark")
		faraday()
		metasploit()
		owaspZAP()
		setoolkit()
	elif mainChoice == "1":
		cmd = os.system("apt-get install -y aircrack-ng")
		time.sleep(2)
	elif mainChoice == "2":
		cmd = os.system("apt-get install -y dsniff")
		time.sleep(2)
	elif mainChoice == "3":
		faraday()
	elif mainChoice == "4":
		cmd = os.system("apt-get install -y hping3")
		time.sleep(2)
	elif mainChoice == "5":
		metasploit()
	elif mainChoice == "6":
		cmd = os.system("apt-get install -y netcat")
		time.sleep(2)
	elif mainChoice == "7":
		cmd = os.system("apt-get install -y nmap")
		time.sleep(2)
	elif mainChoice == "8":
		owaspZAP()
	elif mainChoice == "9":
		setoolkit()
	elif mainChoice == "10":
		cmd = os.system("apt-get install -y wireshark")
		time.sleep(2)
	else:
		print "Please choose a valid option!!!"
		time.sleep(2)

def wirelessMenu():
	print'''
-----------------------------Wireless Tools------------------------------
1) Aircrack-NG						8) GQRX
2) Bluelog						9) Kismet
3) Bluemaho						10) PixieWPS
4) Bluepot						11) Reaver
5) Blueranger						12) Wifite
6) Bluesnarfer						13) Wifi Honey
7) BTScanner		                                14) Fern-Wifi-Cracker

0) Install All
'''
	mainChoice = raw_input("Choose an option: ")
	if mainChoice == "back":
		main()
	elif mainChoice == "home":
		main()
	elif mainChoice == "help":
		HELP()
	elif mainChoice == "0":
		cmd = os.system("apt-get install -y aircrack-ng kismet reaver wifite")
		bluelog()
		bluemaho()
		bluepot()
		blueranger()
		gqrx()
		pixieWPS()
		wifihoney()
		time.sleep(2)
	elif mainChoice == "1":
		cmd = os.system("apt-get install -y aircrack-ng")
		time.sleep(2)
	elif mainChoice == "2":
		bluelog()
	elif mainChoice == "3":
		bluemaho()
	elif mainChoice == "4":
		bluepot()
	elif mainChoice == "5":
		blueranger()
	elif mainChoice == "6":
		print "Comming Soon!"
		time.sleep(2)
	elif mainChoice == "7":
		print "Comming Soon!"
		time.sleep(2)
	elif mainChoice == "8":
		gqrx()
	elif mainChoice == "9":
		cmd = os.system("apt-get install -y kismet")
		time.sleep(2)
	elif mainChoice == "10":
		pixieWPS()
	elif mainChoice == "11":
		cmd = os.system("apt-get install -y reaver")
		time.sleep(2)
	elif mainChoice == "12":
		cmd = os.system("apt-get install -y wifite")
		time.sleep(2)
	elif mainChoice == "13":
		wifihoney()
	elif mainChoice == "14":
		fern()
	else:
		print "Please choose a valid option!!!"
		time.sleep(2)

def webMenu():
	print'''
-----------------------------Web Hacking Tools------------------------------
1) BurpSuite						10) SQLMap
2) BeEF							11) SSLSplit
3) Dirbuster						12) SSLstrip
4) Hping3						13) Vega
5) Metaspoit + Armitage					14) Webshells
6) NMap							15) Websploit
7) Nikto						16) Wireshark
8) OWASP ZAP						17) WPScaner
9) Recon-ng

0) Install All
	'''	

	mainChoice = raw_input("Choose an option: ")
	if mainChoice == "back":
		main()
	elif mainChoice == "home":
		main()
	elif mainChoice == "help":
		HELP()
	elif mainChoice == "0":
		cmd = os.system("apt-get install -y hping3 nmap nikto sqlmap sslsplit sslstrip wireshark")
		burpsuite()
		beef()
		dirbuster()
		metasploit()
		owaspZAP()
		reconNG()
		vega()
		webshells()
		websploit()
		wpscan()
		time.sleep(2)
	elif mainChoice == "1":
		burpsuite()
	elif mainChoice == "2":
		beef()
	elif mainChoice == "3":
		dirbuster()
	elif mainChoice == "4":
		cmd = os.system("apt-get install -y hping3")
		time.sleep(2)
	elif mainChoice == "5":
		metasploit()
	elif mainChoice == "6":
		cmd = os.system("apt-get install -y nmap")
		time.sleep(2)
	elif mainChoice == "7":
		cmd = os.system("apt-get install -y nikto")
		time.sleep(2)
	elif mainChoice == "8":
		owaspZAP()
	elif mainChoice == "9":
		reconNG()
	elif mainChoice == "10":
		cmd = os.system("apt-get install -y sqlmap")
		time.sleep(2)
	elif mainChoice == "11":
		cmd = os.system("apt-get install -y sslsplit")
		time.sleep(2)
	elif mainChoice == "12":
		cmd = os.system("apt-get install -y sslstrip")
		time.sleep(2)
	elif mainChoice == "13":
		vega()
	elif mainChoice == "14":
		webshells()
	elif mainChoice == "15":
		websploit()
	elif mainChoice == "16":
		cmd = os.system("apt-get install -y wireshark")
		time.sleep(2)
	elif mainChoice == "17":
		wpscan()
	else:
		print "Please choose a valid option!!!"
		time.sleep(2)

def	sniffingMenu():
	print'''	 
-----------------------------Sniffing & Spoofing------------------------------
1) Driftnet						6) Netdiscover
2) Dsniff						7) SSLSplit
3) Etherape						8) SSLstrip
4) Ettercap						9) Wireshark
5) Evilgrade                

0) Install All
	'''
	
	mainChoice = raw_input("Choose an option: ")
	if mainChoice == "back":
		main()
	elif mainChoice == "home":
		main()
	elif mainChoice == "help":
		HELP()
	elif mainChoice == "0":
		cmd = os.system("apt-get install -y driftnet dsniff etherape ettercap netdiscover sslsplit sslstrip wireshark")
		evilgrade()
		time.sleep(2)
	elif mainChoice == "1":
		cmd = os.system("apt-get install -y driftnet")
		time.sleep(2)
	elif mainChoice == "2":
		cmd = os.system("apt-get install -y dsniff")
		time.sleep(2)
	elif mainChoice == "3":
		cmd = os.system("apt-get install -y etherape")
		time.sleep(2)
	elif mainChoice == "4":
		cmd = os.system("apt-get install -y ettercap")
		time.sleep(2)
	elif mainChoice == "5":
		evilgrade()
	elif mainChoice == "6":
		cmd = os.system("apt-get install -y netdiscover")
		time.sleep(2)
	elif mainChoice == "7":
		cmd = os.system("apt-get install -y sslsplit")
		time.sleep(2)
	elif mainChoice == "8":
		cmd = os.system("apt-get install -y sslstrip")
		time.sleep(2)
	elif mainChoice == "9":
		cmd = os.system("apt-get install -y wireshark")
		time.sleep(2)
	else:
		print "Please choose a valid option!!!"
		time.sleep(2)

def explotationMenu():
	print'''
------------------------------Exploitation Tools------------------------------
1) BeEF						5) Maltego
2) Evilgrade					6) Metaspoit + Armitage
3) ExploitDB					7) SET
4) Faraday					8) SQLmap			
9) Fierce
0) Install All
	'''

	mainChoice = raw_input("Choose an option: ")
	if mainChoice == "back":
		main()
	elif mainChoice == "home":
		main()
	elif mainChoice == "help":
		HELP()
	elif mainChoice == "0":
		cmd = os.system("apt-get install -y sqlmap")
		beef()
		evilgrade()
		exploitdb()
		faraday()
		maltego()
		metasploit()
		setoolkit()
		time.sleep(2)
	elif mainChoice == "1":
		beef()
	elif mainChoice == "2":
		evilgrade()
	elif mainChoice == "3":
		exploitdb()
	elif mainChoice == "4":
		faraday()
	elif mainChoice == "5":
		maltego()
	elif mainChoice == "6":
		metasploit()
	elif mainChoice == "7":
		setoolkit()
	elif mainChoice == "8":
		cmd = os.system("apt-get install -y sqlmap")
		time.sleep(2)
	elif mainChoice == "9":
		fierce()
	else:
		print "Please choose a valid option!!!"
		time.sleep(2)

def passwordMenu():
	print'''
-------------------------------Password Attacks-------------------------------

1) Bkhive					5) John the ripper
2) Findmyhash					6) Ophcrack
3) Hashcat					7) Samdump2
4) Hydra

0) Install All
	'''

	mainChoice = raw_input("Choose an option: ")
	if mainChoice == "back":
		main()
	elif mainChoice == "home":
		main()
	elif mainChoice == "help":
		HELP()
	elif mainChoice == "0":
		cmd = os.system("apt-get install -y bkhive hydra john ophcrack samdump2")
		findmyhash()
		hashcat()
		time.sleep(2)
	elif mainChoice == "1":
		cmd = os.system("apt-get install -y bkhive")
		time.sleep(2)
	elif mainChoice == "2":
		findmyhash()
	elif mainChoice == "3":
		hashcat()
	elif mainChoice == "4":
		cmd = os.system("apt-get install -y hydra")
		time.sleep(2)
	elif mainChoice == "5":
		cmd = os.system("apt-get install -y john")
		time.sleep(2)
	elif mainChoice == "6":
		cmd = os.system("apt-get install -y ophcrack")
		time.sleep(2)
	elif mainChoice == "7":
		cmd = os.system("apt-get install -y samdump2")
		time.sleep(2)
	else:
		print "Please choose a valid option!!!"
		time.sleep(2)

def reportMenu():
	print'''
-----------------------------Reporting Tools-----------------------------
1) Casefile										
2) CutyCapt
3) Faraday
4) Maltego


0) Install All
	'''

	mainChoice = raw_input("Choose an option: ")
	if mainChoice == "back":
		main()
	elif mainChoice == "home":
		main()
	elif mainChoice == "help":
		HELP()
	elif mainChoice == "0":
		cmd = os.system("apt-get install -y cutycapt")
		casefile()
		faraday()
		maltego()
		time.sleep(2)
	elif mainChoice == "1":
		casefile()
	elif mainChoice == "2":
		cmd = os.system("apt-get install -y cutycapt")
		time.sleep(2)
	elif mainChoice == "3":
		faraday()
	elif mainChoice == "4":
		maltego()
	else:
		print "Please choose a valid option!!!"
		time.sleep(2)

def nfcMenu():
	print'''
-------------------------------NFC Tools---------------------------------
1) LibNFC									
2) MFOK
3) MFCUK
4) PCSC Tools
5) Mfdread
6) Libfreefare (Coming Soon)


0) Install All (Recomended)
	'''

	mainChoice = raw_input("Choose an option: ")
	if mainChoice == "back":
		main()
	elif mainChoice == "home":
		main()
	elif mainChoice == "help":
		HELP()
	elif mainChoice == "0":
		cmd = os.system("apt-get install -y libccid pcscd libpcsclite1 libpcsclite-dev libpcsc-perl pcsc-tools libusb-dev && service pcscd start")
		libnfc()
		mfcuk()
		mfok()
		libfreefare()
		mfdread()
		time.sleep(2)
	elif mainChoice == "1":
		libnfc()
	elif mainChoice == "2":
		mfok()
	elif mainChoice == "3":
		mfcuk()
	elif mainChoice == "4":
		cmd = os.system("apt-get install -y libccid pcscd libpcsclite1 libpcsclite-dev libpcsc-perl pcsc-tools libusb-dev && service pcscd start")
	elif mainChoice == "5":
		mfdread()
	elif mainChoice == "6":
		#libfreefare()
		print "Coming Soon"
		time.sleep(2)
	else:
		print "Please choose a valid option!!!"
		time.sleep(2)

def HELP():
	print'''

  #####                               #####                
 #     # #        ##    ####  #    # #     # ######  ####  
 #       #       #  #  #    # #   #  #       #      #    # 
  #####  #      #    # #      ####    #####  #####  #      
       # #      ###### #      #  #         # #      #      
 #     # #      #    # #    # #   #  #     # #      #    # 
  #####  ###### #    #  ####  #    #  #####  ######  ####  
					 By Franc205


Select the application you want to install and it will be automatically installed.
	*Type "back" on any time to return to the previous screen.
	*Type "help" on any screen to display this message.
	*To exit the application use Ctrl + C
--------------------------------------------------------------------------------
	'''					
	time.sleep(4)

main()

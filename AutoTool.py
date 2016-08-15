#!/usr/bin/python

import os
import sys, traceback
import struct, time

def intallAll():
	cmd = os.system("apt-get install -y wget git curl")
	cmd = os.system("apt-get install -y aircrack-ng sqlmap arduino wireshark sslstrip nmap hping3 amap-align kismet reaver cutycapt binwalk john proxychains apktool nikto ettercap-graphical etherape netdiscover driftnet netcat bkhive ophcrack hydra dsniff wifite foremost galleta guymager p0f volatility funkload slowhttptest sslsplit btscanner wifite samdump2")
	beef()
	bluelog()
	bluemaho()
	bluepot()
	blueranger()
	burpsuite()
	casefile()
	dirbuster()
	evilgrade()
	exploitdb()
	faraday()
	findmyhash()
	hashcat()
	maltego()
	metasploit()
	openvas()
	pixieWPS()
	reconNG()
	setoolkit()
	theharvester()
	webshells()
	websploit()
	wifihoney()
	wpscan()
	time.sleep(2)

def maltego():
	cmd = os.system("apt-get install -y wget")
	cmd = os.system("wget \"https://www.paterva.com/malv35/community/MaltegoCarbonCE.v3.5.3.deb\" -O Maltego.deb")
	cmd = os.system("dpkg -i Maltego.deb")
	cmd = os.system("rm -rf Maltego.deb")
	time.sleep(2)

def casefile():
	cmd = os.system("apt-get install -y wget")
	cmd = os.system("wget \"http://www.paterva.com/cf211/MaltegoCaseFile.v2.1.1.8751.deb\" -O Casefile.deb")
	cmd = os.system("dpkg -i Casefile.deb")
	cmd = os.system("rm -rf Casefile.deb")
	time.sleep(2)
	
def theharvester():
	cmd = os.system("apt-get install -y git python-pip python-dev build-essential")
	cmd = os.system("pip install requests")
	cmd = os.system("git clone https://github.com/laramies/theHarvester /usr/share/theharvester")
	cmd = os.system("ln -s /usr/share/theharvester/theHarvester.py /usr/bin/theHarvester")
	cmd = os.system("chmod +x /usr/bin/theHarvester")
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

def exploitdb():
	cmd = os.system("apt-get install -y git")
	cmd = os.system("git clone git://git.kali.org/packages/exploitdb.git /usr/share/exploitdb")
	cmd = os.system("ln -s /usr/share/exploitdb/searchsploit /usr/bin/searchsploit")
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
	
def pixieWPS():
	cmd = os.system("apt-get install -y git build-essential libpcap-dev sqlite3 libsqlite3-dev libssl-dev unzip")
	cmd = os.system("git clone https://github.com/wiire/pixiewps /tmp/pixiewps")
	cmd = os.system("make -C /tmp/pixiewps/src")
	cmd = os.system("make install -C /tmp/pixiewps/src")
	cmd = os.system("rm -rf /tmp/pixiewps")
	time.sleep(2)

def wifihoney():
	cmd = os.system("apt-get install -y git")
	cmd = os.system("git clone git://git.kali.org/packages/wifi-honey.git /usr/share/wifi-honey")
	cmd = os.system("ln -s /usr/share/wifi-honey/wifi_honey.sh /usr/bin/wifihoney")
	cmd = os.system("chmod +x /usr/share/wifi-honey/wifi_honey.sh")
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
	
def websploit():
	cmd = os.system("apt-get install -y wget")
	cmd = os.system("wget \"http://downloads.sourceforge.net/project/websploit/WebSploit%20Framework%20V.3.0.0/WebSploit-Framework-3.0.0.tar.gz?r=https%3A%2F%2Fsourceforge.net%2Fprojects%2Fwebsploit%2F&ts=1467510406&use_mirror=tenet\" -O Websploit.tar.gz")
	cmd = os.system("tar -xf Websploit.tar.gz")
	cmd = os.system("mv websploit /tmp/websploit")
	cmd = os.system("rm -rf Websploit.tar.gz")
	cmd = os.system("cd /tmp/websploit && ./install.sh")	
	time.sleep(2)
	
def wpscan():
	cmd = os.system("sudo apt-get install -y git libcurl4-openssl-dev libxml2 libxml2-dev libxslt1-dev ruby-dev build-essential libgmp-dev")
	cmd = os.system("git clone https://github.com/wpscanteam/wpscan.git /usr/share/wpscan")
	cmd = os.system("cd /usr/share/wpscan && sudo gem install bundler")
	cmd = os.system("cd /usr/share/wpscan && bundle install --without test")
	#wpscan = open("/usr/bin/wpscan", "a+")
	#wpscan.write("cd /usr/share/wpscan/ && ls && echo \"Usage: ./wpscan.rb \"")
	#wpscan.close()
	#cmd = os.system("chmod +x /usr/bin/wpscan")
	print "WPScan has been successfully installed on /usr/share/wpscan"
	#cmd = os.system("ln -s /usr/share/wpscan/wpscan.rb /usr/bin/wpscan")
	time.sleep(2)

def faraday ():
	cmd = os.system("apt-get install -y git")
	cmd = os.system("git clone https://github.com/infobyte/faraday.git /usr/share/faraday-dev")
	cmd = os.system("easy_install -U setuptools")
	cmd = os.system("cd /usr/share/faraday-dev && ./install.sh")
	cmd = os.system("ln -s /usr/share/faraday-dev/faraday.py /usr/bin/python-faraday")
	time.sleep(2)
	
def metasploit():
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
	cmd = os.system("wget \"https://hashcat.net/files/hashcat-3.00.7z\" -O Hashcat.7z")
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

def evilgrade():
	cmd = os.system("apt-get install -y git librpc-xml-perl libdata-dump-perl")
	cmd = os.system("git clone https://github.com/infobyte/evilgrade /usr/share/evilgrade")
	cmd = os.system("chmod +x /usr/share/evilgrade/evilgrade")
	dirbust = open("/usr/bin/evilgrade", "a+")
	dirbust.write("cd /usr/share/evilgrade/ && ./evilgrade")
	dirbust.close()
	cmd = os.system("chmod +x /usr/bin/evilgrade")

def webshells():
	cmd = os.system("apt-get install -y git")
	cmd = os.system("git clone git://git.kali.org/packages/webshells.git /usr/share/webshells")

def main():
	while True:
		print '''
Welcome
0) All the tools
1) Aircrack-NG
2) SQLMap
3) Maltego
4) Casefile
5) Arduino
6) Wireshark
7) SSLstrip
8) NMap
9) theHarvester
10) hping3
11) Recon-ng 
12) SET 
13) Amap
14) ExploitDB
15) Kismet
16) PixieWPS
17) Reaver
18) Wifi Honey
19) CutyCapt
20) BurpSuite
21) Dirbuster
22) Websploit
23) WPScaner
24) Binwalk
25) Faraday
26) Metaspoit + Armitage
27) BeEF
28) Findmyhash
29) John the ripper
30) Proxychains
31) Apktool
32) Nikto
33) Ettercap
34) Etherape
35) Netdiscover
36) Driftnet
37) Netcat
38) Bkhive
39) Ophcrack
40) Hydra
41) Dsniff
42) Hashcat
43) Wifite
44) Foremost
45) Galleta
46) Guymager
47) p0f
48) Volatility
49) Funkload
50) SlowHTTPTest
51) SSLSplit
52) BTScanner
53) Bluelog
54) Bluemaho
55) Bluepot
56) Blueranger
57) Bluesnarfer
58) Evilgrade
59) Webshells
60) Samdump2

		'''

		mainChoice = raw_input("Choose an option: ")
		if mainChoice == "requirements":
			cmd = os.system("apt-get install -y git wget curl")
			time.sleep(2)
		elif mainChoice == "0":
			intallAll()
		elif mainChoice == "1":
			cmd = os.system("apt-get install -y aircrack-ng")
			time.sleep(2)
		elif mainChoice == "2":
			cmd = os.system("apt-get install -y sqlmap")
			time.sleep(2)
		elif mainChoice == "3":
			maltego()
		elif mainChoice == "4":
			casefile()
		elif mainChoice == "5":
			cmd = os.system("apt-get install -y arduino")
			time.sleep(2)
		elif mainChoice == "6":
			cmd = os.system("apt-get install -y wireshark")
			time.sleep(2)
		elif mainChoice == "7":
			cmd = os.system("apt-get install -y sslstrip")
			time.sleep(2)
		elif mainChoice == "8":
			cmd = os.system("apt-get install -y nmap")
			time.sleep(2)
		elif mainChoice == "9":
			theharvester()
		elif mainChoice == "10":
			cmd = os.system("apt-get install -y hping3")
			time.sleep(2)
		elif mainChoice == "11":
			reconNG()
		elif mainChoice == "12":
			setoolkit()
		elif mainChoice == "13":
			cmd = os.system("apt-get install -y amap-align")
			time.sleep(2)
		elif mainChoice == "14":
			exploitdb()
		elif mainChoice == "15":
			cmd = os.system("apt-get install -y kismet")
			time.sleep(2)
		elif mainChoice == "16":
			pixieWPS()
		elif mainChoice == "17":
			cmd = os.system("apt-get install -y reaver")
			time.sleep(2)
		elif mainChoice == "18":
			wifihoney()	
		elif mainChoice == "19":
			cmd = os.system("apt-get install -y cutycapt")
			time.sleep(2)
		elif mainChoice == "20":
			burpsuite()
		elif mainChoice == "21":
			dirbuster()
		elif mainChoice == "22":
			websploit()
		elif mainChoice == "23":
			wpscan() #Experimental
		elif mainChoice == "24":
			cmd = os.system("apt-get install -y binwalk")
			time.sleep(2)
		elif mainChoice == "25":
			faraday() #Experimental 
		elif mainChoice == "26":
			metasploit()	
		elif mainChoice == "27":
			beef()
		elif mainChoice == "28":
			findmyhash()
		elif mainChoice == "29":
			cmd = os.system("apt-get install -y john")
			time.sleep(2)
		elif mainChoice == "30":
			cmd = os.system("apt-get install -y proxychains")
			time.sleep(2)
		elif mainChoice == "31":
			cmd = os.system("apt-get install -y apktool")
			time.sleep(2)
		elif mainChoice == "32":
			cmd = os.system("apt-get install -y nikto")
			time.sleep(2)
		elif mainChoice == "33":
			cmd = os.system("apt-get install -y ettercap-graphical")
			time.sleep(2)
		elif mainChoice == "34":
			cmd = os.system("apt-get install -y etherape")
			time.sleep(2)
		elif mainChoice == "35":
			cmd = os.system("apt-get install -y netdiscover")
			time.sleep(2)
		elif mainChoice == "36":
			cmd = os.system("apt-get install -y driftnet")
			time.sleep(2)
		elif mainChoice == "37":
			cmd = os.system("apt-get install -y netcat")
			time.sleep(2)
		elif mainChoice == "38":
			cmd = os.system("apt-get install -y bkhive")
			time.sleep(2)
		elif mainChoice == "39":
			cmd = os.system("apt-get install -y ophcrack")
			time.sleep(2)
		elif mainChoice == "40":
			cmd = os.system("apt-get install -y hydra")
			time.sleep(2)
		elif mainChoice == "41":
			cmd = os.system("apt-get install -y dsniff")
			time.sleep(2)
		elif mainChoice == "42":
			hashcat()
		elif mainChoice == "43":
			cmd = os.system("apt-get install -y wifite")
			time.sleep(2)
		elif mainChoice == "44":
			cmd = os.system("apt-get install -y foremost")
			time.sleep(2)
		elif mainChoice == "45":
			cmd = os.system("apt-get install -y galleta")
			time.sleep(2)
		elif mainChoice == "46":
			cmd = os.system("apt-get install -y guymager")
			time.sleep(2)
		elif mainChoice == "47":
			cmd = os.system("apt-get install -y p0f")
			time.sleep(2)
		elif mainChoice == "48":
			cmd = os.system("apt-get install -y volatility")
			time.sleep(2)
		elif mainChoice == "49":
			cmd = os.system("apt-get install -y funkload")
			time.sleep(2)
		elif mainChoice == "50":
			cmd = os.system("apt-get install -y slowhttptest")
			time.sleep(2)
		elif mainChoice == "51":
			cmd = os.system("apt-get install -y sslsplit")
			time.sleep(2)
		elif mainChoice == "52":
			cmd = os.system("apt-get install -y btscanner")
			time.sleep(2)
		elif mainChoice == "53":
			bluelog()
		elif mainChoice == "54":
			bluemaho()
		elif mainChoice == "55":
			bluepot()
		elif mainChoice == "56":
			blueranger()
		elif mainChoice == "57":
			bluesnarfer()
		elif mainChoice == "58":
			evilgrade()
		elif mainChoice == "59":
			webshells()
		elif mainChoice == "60":
			cmd = os.system("apt-get install -y samdump2")
		else:
			print "Please choose a valid option!!!"
			time.sleep(2)
					

main()

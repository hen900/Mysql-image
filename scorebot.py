# coding: utf=8
from __future__ import division
import os
import sys
import time


class Vuln:

    def __init__(self, desc, val, boolean):
        self.desc = desc
        self.boolean = boolean
        self.val = val

    def getValue(self):
        return self.val

    def getDescription(self):
        return self.desc

    def isFixed(self):
        if os.system(self.boolean) == 0:
            return True
        else:
            return False


class Service:

    def __init__(self, name):
        self.name = name

    def getName(self):
        return self.name

    def isDown(self):
        if self.name == "mysql":
                if os.system('service  '+  self.name + ' status | grep start') != 0 or  os.system('ls /var/lib/mysql | grep memberInfo')  != 0:
                        return True
        if self.name == "ssh":
                if os.system('service  '+  self.name + ' status | grep start')  != 0:
                        return True
        return False
    


class User:

    def __init__(self, name):
        self.name = name

    def getName(self):
        return self.name

    def works(self):
        if os.system(' [ -e /home/' + self.name + '/ ]') \
            + os.system(' [ "$(grep ' + self.name + ' /etc/passwd)" ]') \
            == 0:
            return True

        return False
    def isAdmin(self):
        if os.system('grep sudo /etc/group| grep ' + self.name) == 0:
            return True
        return False


def update():
    percent = str(round(points / totalPoints * 100, 1)) + '%'
    with open('/home/'+mainUser+'/Desktop/Report.html', 'w') as f:
        f.write('<!DOCTYPE html> <html> <head> <meta name="viewport" content="width=device-width, initial-scale=1"> <style> * { box-sizing: border-box; } .column { float: left; padding: 10px; height: 1500px; } .left, .right { width: 25%; } .middle { width: 50%; } .row:after { content: ""; display: table; clear: both; }</style> </head> <body><div class="row"> <div class="column left" style="background-color:#0d60bf;"></div> <div class="row"> <div class="column middle" style="background-color:#fff;"><h1 style="text-align: center;"><span style="font-family: arial, helvetica, sans-serif;">MySQL Image</span></h1><h2 style="text-align: center;"><br /><span style="font-family: arial, helvetica, sans-serif;">'
                 + percent + ' completed</span></h2><p> </p>')
        f.write('<p><span style="font-family: arial, helvetica, sans-serif;"><strong>'
                 + str(penalties)
                + ' Points in Scoring Penalties</strong></span></p> <font color="red">'
                )
        for i in services:
            if i.isDown():
                f.write('<p><span style="font-size: 10pt;  font-family: arial, helvetica, sans-serif;">'
                         + i.getName()
                        + ' not functional - 5 points</span></p>')
        for i in users:
            if not i.works():
                f.write('<p><span style="font-size: 10pt;  font-family: arial, helvetica, sans-serif;"> User '
                         + i.getName()
                        + ' not functional - 5 points</span></p>')

        for i in admins:
           if not i.works():
                f.write('<p><span style="font-size: 10pt;  font-family: arial, helvetica, sans-serif;"> User '
                         + i.getName()
                        + ' not functional - 5 points</span></p>')

        f.write('</font><p><span style="font-family: arial, helvetica, sans-serif;"><strong>'
                 + str(numFixedVulns) + ' out of ' + str(numVulns)
                + '  Vulnerabilities Fixed</strong></span></p>\n')
        for i in allVulns:
            if i.isFixed():
                f.write('<p><span style="font-size: 10pt; font-family: arial, helvetica, sans-serif;">'
                         + i.getDescription() + ' - '
                        + str(i.getValue()) + ' points</span></p>')
        f.write('</div> <div class="row"> <div class="column right" style="background-color:#0d60bf;"></div> </body>'
                )
        f.write('<meta http-equiv="refresh" content="20">')
        f.write('<footer><h6>Henry Mackay</h6></footer>')


mainUser = 'bcpl_admin'
users = [User('eric_rodgers'), User('boe34_'), User('ken_grimwood'), User('monte3'), User('je3rryg'), User('june_w'), User('anne_pallad'), User('krist0benway')]
admins = [User('bcpl_admin'), User('benjamin'), User('swagrobot'), User('andy76')]
services = [Service('ssh'), Service('mysql')]
allVulns = [
	Vuln('Forensics Question 1 correct', 8, '[ "$(grep "16237.382" /home/'+ mainUser + '/Desktop/Forensics_1.txt)" ]'),
	Vuln('Forensics Question 2 correct', 8, '[ "$(grep "2.4.18" /home/'+ mainUser + '/Desktop/Forensics_2.txt)" ]'),
	Vuln('Forensics Question 3 correct', 8, '[ "$(grep "/usr/local/srcd/.s3cr3t" /home/'+ mainUser + '/Desktop/Forensics_3.txt)" ]'),
	Vuln('Netcat backdoor disabled', 4, '! [ "$(netstat -tulpn | grep cupsd | grep 654)" ]'),
	Vuln('Removed unauthorized user corn23', 1,'! [ "$(grep corn23  /etc/passwd)" ]'),
	Vuln('Removed unauthorized user batman', 1,'! [ "$(grep batman  /etc/passwd)" ]'),
	Vuln('Removed unauthorized admin boe34_ ', 1,'! [ "$(grep sudo /etc/group | grep boe34_)" ]'),
	Vuln('Added authorized admin andy76', 1,'[ "$(grep sudo /etc/group | grep andy76)" ]'),
	Vuln('Removed unauthorized admin monte3 ', 1,'! [ "$(grep sudo /etc/group | grep monte3)" ]'),
	Vuln('Login retries set', 2,'[ "$(grep LOGIN_RETRIES /etc/login.defs | grep 3)" ]'),
	Vuln('Guest account is disabled', 1,'[ "$(grep guest /etc/lightdm/lightdm.conf | grep false)" ] '),
	Vuln('Firewall protection enabled', 2,'[ "$(ufw status verbose  | grep "Default: deny (incoming)" )" ] '),
	Vuln('Root login disabled for ssh', 2,'[ "$(grep PermitRootLogin /etc/ssh/sshd_config | grep -i no)" ]'),
	Vuln('Password required for sudo', 2,'! [ "$(grep NOPASSWD /etc/sudoers.d/README)" ]'),
	Vuln('Password policy enforced', 2,' [ "$( grep cracklib /etc/pam.d/common-password | grep ocredit)" ] '),
	Vuln('Security updates automatically installed', 2,' [ "$(grep -r Unattended /etc/apt| grep 1)" ] '),
	Vuln('Keylogger removed', 3, ' ! [ "$(dpkg --list | grep logkeys| grep ii )" ]'),
	Vuln('Ophcrack hacking tool removed', 3, ' ! [ "$( ls /usr/bin/ophcrack)" ]'),
	Vuln('VNC server removed', 3, ' ! [ "$( ls /usr/bin/tightvncserver)" ]'),
	Vuln('ASLR Randomization enabled', 2,' [ "$(sysctl -a | grep va_randomize_space | grep 2)" ] '),
	Vuln('Martian Packets are logged', 2,' [ "$(sysctl -a | grep net.ipv4.conf.default.log_martians | grep 1)" ] '),
	Vuln('Correct permissions set on passwd', 3,'[ "$(stat -c %a /etc/passwd | grep 644)" ] '),
	Vuln('A sticky bit is set on /tmp', 2,'[ "$(stat -c %a /etc/passwd | grep 177)" ] '),
	Vuln('lighttpd server removed or disabled', 2,' ! [ "$(netstat -tulpn | grep lighttpd)" ] '),
	Vuln('Malicious domain redirection removed', 3,' ! [ "$(grep -E irs.gov /etc/hosts)" ] '),
	Vuln('Insecure password for benjamin changed', 1, '! [ "$(grep benjamin /etc/shadow | grep Bcmz)" ]'),
	Vuln('Root is not given a direct login', 2, '[ "$(grep root /etc/shadow | grep "!")" ]'),
	Vuln('Mysql cannot load local files', 3, '[ "$(grep local-infile /etc/mysql/my.cnf | grep 0)" ]'),
	Vuln('Mysql is not running as root', 3, ' ! [ "$(ps aux | grep -v "grep" | grep mysqld | grep root )" ] && [ "$(service mysql status | grep running)" ]'),
	Vuln('Mysql running on the correct port', 3, ' [ "$(netstat -tulpn | grep mysql | grep 3306 )" ]'),
	Vuln('Mysql database containing sensitve information removed', 3, '! [ "$(ls /var/lib/mysql | grep passwords)" ]'),
	Vuln('Mysql cannot load local files', 3, '[ "$(grep local-infile /etc/mysql/my.cnf | grep 0)" ]'),
	Vuln('Mysql remote access is enabled', 2, '[ "$(netstat -tulpn | grep mysqld| grep "0 0.0.0.0" )" ]'),
	Vuln('SSL is enabled for MySQL', 4, '[ "$(mysql -u root -ppassword -e status | grep SSL | grep -v "Not in use")" ]'),
	Vuln('DNS server disabled or removed', 2, '! [ "$(service bind9 status| grep "bind9 is running")" ]'),
	Vuln('Fork bomb protection enabled', 2, '[ "$(grep hard /etc/security/limits.conf| grep core | grep "*")" ]'),
	Vuln('IPv6 is disabled', 2,'[ "$(grep net.ipv6.conf.all.disable_ipv6 /etc/sysctl.conf | grep 1)" ]')
    ]


numVulns = len(allVulns)

while True:
    totalPoints = 0
    points = 0
    numFixedVulns = 0
    penalties = 0
    for i in services:
        if i.isDown():
            penalties = penalties + 5

    for i in users:
        if not i.works():
            penalties = penalties + 5
    for i in admins:
        if not i.works():
            penalties= penalties + 5
    for i in allVulns:
        totalPoints = totalPoints + i.getValue()
        print i.getDescription()
        if i.isFixed():
            numFixedVulns = numFixedVulns + 1
            points = points + i.getValue()

    points = points - penalties

    update()
    time.sleep(60)

			

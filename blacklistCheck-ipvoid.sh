#!/usr/bin/env bash
#Author: Matthew Riedle
#Version: 1.1

## CHANGE NOTES

# 1.0
# Added blacklists from IPVoid. Current count is 114.

# 1.1
# Added new blacklists. New count is 129

## END CHANGE NOTES


# The script needs to be executed as ./blacklistCheck.sh IPs.txt
# IPs.txt needs to contain a list of IPv4 Addresses separated on new lines
ips=$1

# Loading the list of emails / usernames into a list
IFS=$'\n' read -d '' -r -a list < $ips

# Defining some variables
count=1
incrementer=1

# Reverse IP Function
reverseip () {
    local IFS
    IFS=.
    set -- $1
    echo $4.$3.$2.$1
}

# Create an array with various UserAgents
UAarray=('User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.867.36' 'User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36' 'User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36' 'User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko' 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:66.0) Gecko/20100101 Firefox/66.0')

# Create random generator
Random=$$$(date +%s)

# This will check if the results file already exists. If not, it will create one with the proper headings
file=./BlacklistCheckResults.txt
if [ -e "$file" ]; then
    echo ""
else 
    touch $file
fi

echo "Lookup is starting."
echo "Number of IPs loaded for lookup: " ${#list[@]}
echo "Number of Blacklists loaded for lookup: 129"
#echo ${list[@]}

# For every URL listed in the URLS.txt, each of the attacks below will be executed
for line in ${list[@]}; do

# Set the current UserAgent
	UserAgent=${UAarray[$Random % ${Random[*]}]}
#echo $UserAgent

# Reverse the IP for dig lookups
	reverseIP=$(reverseip $line)

# Set / Reset the Blacklist Count
	blacklistCount=0

# Add spacers to the beginning of the results
	echo "==========" >> $file

# Add the email / username being queried
	echo $line >> $file
	echo "" >> $file
	
# Reset the timestamp to the current time and use PST
	timestamp=$(TZ=":America/Los_Angeles" date)
	
# Echo the current line number
    echo "Entry #"$count >> $file

# Load the current time into the file to record what time the HIBP Lookup was performed
	echo -e "$timestamp" >> $file

# Notify that blacklist check is starting
	echo "Starting blacklist check on $line"

sleep 0.25
# Blacklist 1 - AlienVault Reputation
	curl -s -H "$UserAgent" https://otx.alienvault.com/api/v1/indicators/IPv4/$line/reputation | grep -q 'Malicious Host'

	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 1 Checked"


sleep 0.25
# Blacklist 2 - Anti-Attacks BL
	curl -s -H "$UserAgent" https://www.anti-attacks.com/daten-abfrage/?abfrage_ip=$line | grep -q 'banned'
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 2 Checked"
	

sleep 0.25
# Blacklist 3 - AntiSpam_by_CleanTalk
	curl -s -H "$UserAgent" https://cleantalk.org/blacklists/$line | grep -q 'reported as spam'
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 3 Checked"


sleep 0.25
# Blacklist 4 - Autoshun
	curl -s -H "$UserAgent" https://autoshun.org/downloads/storm-addrs-710.rules | grep -q $line
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 4 Checked"


sleep 0.25
# Blacklist 5 - Backscatterer
	curl -s -X POST -H "$UserAgent" -H 'Referer: http://www.backscatterer.org/index.php?target=test' http://www.backscatterer.org/index.php -d "target=test&ip=$line&PHPSESSID=1moplbreru4sojli7kgno7scj4" | grep -q 'IS CURRENTLY LISTED'
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 5 Checked"


sleep 0.25
# Blacklist 6 - BadIPs
	curl -s -H "$UserAgent" https://www.badips.com/info/$line | grep -q 'was reported for malicious activity'
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 6 Checked"


sleep 0.25
# Blacklist 7 - BBcan177 (pfBlockerNG) - MS-1
	curl -s -H "$UserAgent" https://gist.githubusercontent.com/BBcan177/bf29d47ea04391cb3eb0/raw/f7b3779da1c490b57e9ad892534b36b3836afe61/MS-1 | grep -q $line
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 7 Checked"


sleep 0.25
# Blacklist 8 - BinaryDefense Ban List
	curl -s -H "$UserAgent" https://www.binarydefense.com/banlist.txt | grep -q $line
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 8 Checked"


sleep 0.25
# Blacklist 9 - Blacklists_co
	curl -s -H "$UserAgent" http://blacklists.co/download/all.txt | grep -q $line
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 9 Checked"


sleep 0.25
# Blacklist 10-17 - BlockedServersRBL
	dig +short A $reverseIP.rbl.efnet.org | grep -q '127.0.0.1'
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 10 Checked"
	
	
	dig +short A $reverseIP.dnsbl.dronebl.org | grep -q '127.0.0.1'
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 11 Checked"
	
	
	dig +short A $reverseIP.ips.backscatterer.org | grep -q '127.0.0.2'
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 12 Checked"
	
	
	dig +short A $reverseIP.rbl.abuse.ro | grep -q '127.0.0.2'
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 13 Checked"
	
	
	dig +short A $reverseIP.b.barracudacentral.org | grep -q '127.0.0.2'
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 14 Checked"
	
	
	dig +short A $reverseIP.bl.blocklist.de | grep -q '127.0.0.2'
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 15 Checked"
	
	
	dig +short A $reverseIP.spam.rbl.blockedservers.com | grep -q '127.0.0.10'
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 16 Checked"
	
	
	dig +short A $reverseIP.netscan.rbl.blockedservers.com | grep -q '127.0.0.10'
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 17 Checked"


sleep 0.25
# Blacklist 18 - Blocklist.net.ua
	curl -s -H "$UserAgent" https://blocklist.net.ua/check/?ip=$line | grep -q 'span id="notlock">ЗАБЛОКИРОВАН'
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 18 Checked"


sleep 0.25
# Blacklist 19 - BlockList_de
	curl -s -H "$UserAgent" https://lists.blocklist.de/lists/all.txt | grep -q $line
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 19 Checked"


sleep 0.25
# Blacklist 20-21 - BlogSpamBL
	dig +short A $reverseIP.backscatter.spameatingmonkey.net | grep -q '127.0.0.2'
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 20 Checked"
	

	dig +short A $reverseIP.bl.spameatingmonkey.net | grep -q '127.0.0.2'
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 21 Checked"
	

sleep 0.25
# Blacklist 22 - Botvrij.eu
	curl -s -H "$UserAgent" http://botvrij.eu/data/ioclist.ip-dst.raw | grep -q $line
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 22 Checked"


sleep 0.25
# Blacklist 23 - Brute Force Blocker
	curl -s -H "$UserAgent" http://danger.rulez.sk/projects/bruteforceblocker/blist.php | grep -q $line

	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 23 Checked"


sleep 0.25
# Blacklist 24 - Bytefarm_ch IP BL
	curl -s -X POST -H "$UserAgent" -H 'Referer: https://www.bytefarm.ch/fail2ban/' https://www.bytefarm.ch/fail2ban/ -d "q=$line&s=ip&submit=search" | grep -q 'valign="top">'$line
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 24 Checked"


sleep 0.25
# Blacklist 25-27 - CBL_AbuseAt
	dig +short A $reverseIP.zen.spamhaus.org | grep -q '127.0.0.2\|127.0.0.3\|127.0.0.4\|127.0.0.5\|127.0.0.6\|127.0.0.7'
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 25 Checked"
	
	
	dig +short A $reverseIP.zen.spamhaus.org | grep -q '127.0.0.2\|127.0.0.3\|127.0.0.4\|127.0.0.5\|127.0.0.6\|127.0.0.7'
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 26 Checked"
	
	
	dig +short A $reverseIP.zen.spamhaus.org | grep -q '127.0.0.2\|127.0.0.3\|127.0.0.4\|127.0.0.5\|127.0.0.6\|127.0.0.7'

	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 27 Checked"


sleep 0.25
# Blacklist 28 - CERT-PA
	curl -s -H "$UserAgent" https://infosec.cert-pa.it/analyze/listip.txt | grep -q $line
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 28 Checked"


sleep 0.25
# Blacklist 29-31 - Charles Haley
	curl -s -H "$UserAgent" http://www.the-haleys.com/chaley/ssh_dico_attack_hdeny_format.php/hostsdeny.txt | grep -q $line
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 29 Checked"


	curl -s -H "$UserAgent" http://charles.the-haleys.org/wp_attack_with_timestamps.php | grep -q $line
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 30 Checked"


	curl -s -H "$UserAgent" http://charles.the-haleys.org/smtp_dico_attack_with_timestamps.php | grep -q $line
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 31 Checked"


sleep 0.25
# Blacklist 32 - CI Army List
	curl -s -H "$UserAgent" http://cinsscore.com/list/ci-badguys.txt | grep -q $line
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 32 Checked"


sleep 0.25
# Blacklist 33 - CSpace Hostings IP BL
	curl -s -H "$UserAgent" http://netset.cspacehostings.com/IP.txt | grep -q $line
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 33 Checked"


sleep 0.25
# Blacklist 34 - Cybercrime-tracker.net
	curl -s -H "$UserAgent" http://cybercrime-tracker.net/index.php?search=$line | grep -q 'target="_blank">'$line
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 34 Checked"


sleep 0.25
# Blacklist 35 - CyberCure
	curl -s -H "$UserAgent" http://api.cybercure.ai/feed/get_ips?type=list | grep -q $line
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 35 Checked"


sleep 0.25
# Blacklist 36 - Darklist.de
	curl -s -H "$UserAgent" http://www.darklist.de/raw.php | grep -q $line
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 36 Checked"


sleep 0.25
# Blacklist 37-43 - DataPlane.org
	curl -s -H "$UserAgent" https://dataplane.org/sipregistration.txt | grep -q $line
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 37 Checked"


	curl -s -H "$UserAgent" https://dataplane.org/sipinvitation.txt | grep -q $line
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 38 Checked"


	curl -s -H "$UserAgent" https://dataplane.org/sipquery.txt | grep -q $line
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 39 Checked"


	curl -s -H "$UserAgent" https://dataplane.org/sshclient.txt | grep -q $line
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 40 Checked"


	curl -s -H "$UserAgent" https://dataplane.org/sshpwauth.txt | grep -q $line
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 41 Checked"


	curl -s -H "$UserAgent" https://dataplane.org/dnsrd.txt | grep -q $line
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 42 Checked"


	curl -s -H "$UserAgent" https://dataplane.org/vncrfb.txt | grep -q $line
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 43 Checked"


sleep 0.25
# Blacklist 44 - DNSBL_AbuseCH
	curl -s -H "$UserAgent" https://ransomwaretracker.abuse.ch/downloads/RW_IPBL.txt | grep -q $line
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 44 Checked"


sleep 0.25
# Blacklist 45 - Bytefarm
	curl -s -X POST -H "$UserAgent" -H 'Referer: https://www.bytefarm.ch/fail2ban/' https://www.bytefarm.ch/fail2ban/ -d "q=$line&s=ip&submit=search" | grep -q '<a href="viewlog?ip='
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 45 Checked"


sleep 0.25
# Blacklist 46 - EmergingThreats
	curl -s -H "$UserAgent" https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt | grep -q $line
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 46 Checked"


sleep 0.25
# Blacklist 47 - Ens160 SSH BL
	curl -s -H "$UserAgent" https://ens160.com/blacklist/$line | grep -q 'is blacklisted'
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 47 Checked"


sleep 0.25
# Blacklist 48 - Etnetera BL
	curl -s -H "$UserAgent" https://security.etnetera.cz/feeds/etn_aggressive.txt | grep -q $line
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 48 Checked"


sleep 0.25
# Blacklist 49 - GPF DNS Block List
	curl -s -X POST -H "$UserAgent" -H 'Referer: https://www.gpf-comics.com/dnsbl/export.php' https://www.gpf-comics.com/dnsbl/export.php -d 'ipv6=0&export_type=text&submit=Export' | grep -q $line
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 49 Checked"


sleep 0.25
# Blacklist 50 - GreenSnow Blocklist
	curl -s -H "$UserAgent" https://blocklist.greensnow.co/greensnow.txt | grep -q $line
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 50 Checked"


sleep 0.25
# Blacklist 51 - InterServer IP List
	curl -s -H "$UserAgent" https://sigs.interserver.net/ip?ip=$line | grep -q '<br><b>ID'
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 51 Checked"


sleep 0.25
# Blacklist 52 - IPSum
	curl -s -H "$UserAgent" https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt | grep -q $line
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 52 Checked"


sleep 0.25
# Blacklist 53 - Ip-finder.me
	curl -s -H "$UserAgent" https://www.ip-finder.me/$line/ | grep -q 'is blacklisted by'
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 53 Checked"


sleep 0.25
# Blacklist 54 - JustSpam_org
	dig +short A $reverseIP.dnsbl.justspam.org | grep -q '127.0.0.2'
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 54 Checked"


sleep 0.25
# Blacklist 55 - LashBack UBL
	curl -s -H "$UserAgent" http://www.unsubscore.com/blacklist.txt | grep -q $line
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 55 Checked"


sleep 0.25
# Blacklist 56 - Malc0de
	curl -s -H "$UserAgent" http://malc0de.com/bl/IP_Blacklist.txt | grep -q $line
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 56 Checked"


sleep 0.25
# Blacklist 57 - MalwareDomainList
	curl -s -H "$UserAgent" http://www.malwaredomainlist.com/hostslist/ip.txt | grep -q $line
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 57 Checked"


sleep 0.25
# Blacklist 58 - Matapala_org FW Log
	curl -s -H "$UserAgent" https://log.matapala.org/fw/$line | grep -q 'dpt</th><tr> <td><a href="https://log.matapala.org'
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 58 Checked"


sleep 0.25
# Blacklist 59 - MaxMind High Risk IPs
	curl -s -H "$UserAgent" https://www.maxmind.com/en/high-risk-ip-sample-list | grep -q $line
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 59 Checked"


sleep 0.25
# Blacklist 60 - MegaRBL
	curl -s -H "$UserAgent" https://www.megarbl.net/blocking_list.php?ip=$line| grep -q 'is listed in the RBL'
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 60 Checked"


sleep 0.25
# Blacklist 61 - Ms-ds-violation-ips
#	curl -s -H "$UserAgent" https://raw.githubusercontent.com/conmarap/ms-ds-violation-ips/master/ms-ds-violation-ips.ipset | grep -q $line
#	
#	greprc=$?
#	
#	if [[ $greprc -eq 0 ]] ; then
#		(( blacklistCount++ ))
#	else
#		echo "" >> /dev/null
#	fi
#	
#	echo "Blacklist 61 Checked"


sleep 0.25
# Blacklist 62-65 - NEU SSH Black list
	curl -s -H "$UserAgent" http://antivirus.neu.edu.cn/scan/ssh.php | grep -q $line
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 62 Checked"


#	curl -s -H "$UserAgent" http://antivirus.neu.edu.cn/ssh/lists/neu_smtp.txt | grep -q $line
#	
#	greprc=$?
#	
#	if [[ $greprc -eq 0 ]] ; then
#		(( blacklistCount++ ))
#	else
#		echo "" >> /dev/null
#	fi
#	
#	echo "Blacklist 63 Checked"
#
#
#	curl -s -H "$UserAgent" http://antivirus.neu.edu.cn/ssh/lists/neu.txt | grep -q $line
#	
#	greprc=$?
#	
#	if [[ $greprc -eq 0 ]] ; then
#		(( blacklistCount++ ))
#	else
#		echo "" >> /dev/null
#	fi
#	
#	echo "Blacklist 64 Checked"
#
#
#	curl -s -H "$UserAgent" http://antivirus.neu.edu.cn/ssh/lists/base.txt | grep -q $line
#	
#	greprc=$?
#	
#	if [[ $greprc -eq 0 ]] ; then
#		(( blacklistCount++ ))
#	else
#		echo "" >> /dev/null
#	fi
#	
#	echo "Blacklist 65 Checked"


sleep 0.25
# Blacklist 66 - NiX_Spam
	curl -s -H "$UserAgent" http://www.dnsbl.manitu.net/lookup.php?value=$line | grep -q 'is listed since'
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 66 Checked"


sleep 0.25
# Blacklist 67 - NoIntegrity BL
	curl -s -H "$UserAgent" http://www.nointegrity.org/_support/Firewall/ssh_blockade.txt | grep -q $line
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 67 Checked"


sleep 0.25sleep 0.25
# Blacklist 68 - NordSpam
	dig +short A $reverseIP.bl.nordspam.com | grep -q '127.0.0.2'
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 68 Checked"


sleep 0.25
# Blacklist 69-72 - NoThink.org
	curl -s -H "$UserAgent" http://www.nothink.org/honeypot_dns_attacks.txt | grep -q $line
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 69 Checked"


	curl -s -H "$UserAgent" http://www.nothink.org/blacklist/blacklist_snmp_year.txt | grep -q $line
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 70 Checked"


	curl -s -H "$UserAgent" http://www.nothink.org/blacklist/blacklist_ssh_year.txt | grep -q $line
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 71 Checked"


	curl -s -H "$UserAgent" http://www.nothink.org/blacklist/blacklist_telnet_year.txt | grep -q $line
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 72 Checked"


sleep 0.25
# Blacklist 73 - Pofon_foobar_hu
	curl -s -H "$UserAgent" https://rbl.foobar.hu/pofon/bl?$line | grep -q 'is not listed'
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 73 Checked"


sleep 0.25
# Blacklist 74 - Redstout Threat IP 
	curl -s -H "$UserAgent" http://redlist.redstout.com/redlist.txt | grep -q $line
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 74 Checked"


sleep 0.25
# Blacklist 75-79 - Reuteras Scanning
	curl -s -H "$UserAgent" https://attackers.ongoing.today/closed.txt | grep -q $line
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 75 Checked"


	curl -s -H "$UserAgent" https://attackers.ongoing.today/database.txt | grep -q $line
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 76 Checked"


	curl -s -H "$UserAgent" https://attackers.ongoing.today/httpd.txt | grep -q $line
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 77 Checked"


	curl -s -H "$UserAgent" https://attackers.ongoing.today/misc.txt | grep -q $line
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 78 Checked"


	curl -s -H "$UserAgent" https://attackers.ongoing.today/shell.txt | grep -q $line
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 79 Checked"


sleep 0.25
# Blacklist 80-83 - Roquesor BL
	curl -s -H "$UserAgent" https://es.roquesor.com/en/txt/port22.txt | grep -q $line
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 80 Checked"


	curl -s -H "$UserAgent" https://es.roquesor.com/en/txt/port25.txt | grep -q $line
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 81 Checked"


	curl -s -H "$UserAgent" https://es.roquesor.com/en/txt/port995.txt | grep -q $line
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 82 Checked"


	curl -s -H "$UserAgent" https://es.roquesor.com/en/txt/port80.txt | grep -q $line
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 83 Checked"


sleep 0.25
# Blacklist 84 - Rutgers Drop List
	curl -s -H "$UserAgent" https://report.cs.rutgers.edu/mrtg/drop/dropstat.cgi?start=-1y | grep -q $line
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 84 Checked"


sleep 0.25
# Blacklist 85 - S.S.S.H.I.A
	curl -s -H "$UserAgent" https://raw.githubusercontent.com/mitchellkrogza/Suspicious.Snooping.Sniffing.Hacking.IP.Addresses/master/ips.list | grep -q $line
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 85 Checked"


sleep 0.25
# Blacklist 86 - S5hbl
	dig +short A $reverseIP.all.s5h.net | grep -q '127.0.0.2'
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 86 Checked"


sleep 0.25
# Blacklist 87-88 - SANYALnet Labs Mirai
	curl -s -H "$UserAgent" http://sanyalnet-cloud-vps.freeddns.org/blocklist.txt | grep -q $line
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 87 Checked"


	curl -s -H "$UserAgent" http://sanyalnet-cloud-vps.freeddns.org/mirai-ips.txt | grep -q $line
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 88 Checked"


sleep 0.25
# Blacklist 89 - Sblam
	curl -s -H "$UserAgent" https://sblam.com/blacklist.txt | grep -q $line
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 89 Checked"


sleep 0.25
# Blacklist 90 - Scientific_Spam_BL
	dig +short A $reverseIP.bl.scientificspam.net | grep -q '127.0.0.2'

	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 90 Checked"


sleep 0.25
# Blacklist 91 - Snort IPFilter
	curl -s -H "$UserAgent" https://talos-intelligence-site.s3.amazonaws.com/production/document_files/files/000/064/572/original/ip_filter.blf?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIXACIED2SPMSC7GA%2F20190408%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20190408T043432Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&X-Amz-Signature=717ce9315a39915185e8e60cb70cc361eb0057eac113c98ee9dd8d856a6ea04a | grep -q $line
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 91 Checked"


sleep 0.25
# Blacklist 92 - SpamCop
	curl -s -H "$UserAgent" https://www.spamcop.net/w3m?action=checkblock&ip=$line | grep -q 'not listed in bl.spamcop.net'
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		echo "" >> /dev/null
	else
		(( blacklistCount++ ))
	fi
	
	echo "Blacklist 92 Checked"


sleep 0.25
# Blacklist 93-96 - SpamRATS
	dig +short A $reverseIP.dyna.spamrats.com | grep -q '127.0.0.2'
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 93 Checked"
	
	
	dig +short A $reverseIP.noptr.spamrats.com | grep -q '127.0.0.2'
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 94 Checked"
	
	
	dig +short A $reverseIP.spam.spamrats.com | grep -q '127.0.0.2'
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 95 Checked"
	
	
	dig +short A $reverseIP.auth.spamrats.com | grep -q '127.0.0.2'
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 96 Checked"


sleep 0.25
# Blacklist 97-98 - SSL Blacklist
	curl -s -H "$UserAgent" https://sslbl.abuse.ch/blacklist/sslipblacklist_aggressive.txt | grep -q $line
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 97 Checked"


	curl -s -H "$UserAgent" https://sslbl.abuse.ch/blacklist/sslipblacklist_aggressive.rules | grep -q $line
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 98 Checked"


sleep 0.25
# Blacklist 99-100 - St Dominics Priory College
	curl -s -H "$UserAgent" https://threatintel.stdominics.sa.edu.au/droplist_high_confidence.txt | grep -q $line
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 99 Checked"


	curl -s -H "$UserAgent" https://threatintel.stdominics.sa.edu.au/droplist_low_confidence.txt | grep -q $line
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 100 Checked"


sleep 0.25
# Blacklist 101 - Stefan Gofferje
	curl -s -H "$UserAgent" https://www.gofferje.net/it-stuff/sipfraud/sip-attacker-blacklist | grep -q $line
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 101 Checked"


sleep 0.25
# Blacklist 102 - StopForumSpam
	curl -s -H "$UserAgent" http://api.stopforumspam.org/api?ip=$line | grep -q '<appears>yes'
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 102 Checked"


sleep 0.25
# Blacklist 103 - Suomispam_RBL
	dig +short A $reverseIP.bl.suomispam.net | grep -q '127.0.0.2'
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 103 Checked"


sleep 0.25
# Blacklist 104 - Taichung Education
	curl -s -H "$UserAgent" https://www.tc.edu.tw/net/netflow/lkout | grep -q $line
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 104 Checked"


sleep 0.25
# Blacklist 105 - TalosIntel IPFilter
	curl -s -H "$UserAgent" https://talos-intelligence-site.s3.amazonaws.com/production/document_files/files/000/064/575/original/ip_filter.blf?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIXACIED2SPMSC7GA%2F20190408%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20190408T051638Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&X-Amz-Signature=cca827b119ed4a1e12c3ed815eebfe41636235b9840a3774265ba081b139146a | grep -q $line
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 105 Checked"


sleep 0.25
# Blacklist 106 - Threat Crowd
	curl -s -H "$UserAgent" https://www.threatcrowd.org/feeds/ips.txt | grep -q $line
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 106 Checked"


sleep 0.25
# Blacklist 107 - Threat Sourcing
	curl -s -H "$UserAgent" https://www.threatsourcing.com/ipall-free.txt | grep -q $line
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 107 Checked"


sleep 0.25
# Blacklist 108 - URLVir
	curl -s -H "$UserAgent" http://www.urlvir.com/export-ip-addresses/ | grep -q $line
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 108 Checked"


sleep 0.25
# Blacklist 109 - USTC IP BL
	curl -s -H "$UserAgent" http://blackip.ustc.edu.cn/list.php?s=t | grep -q $line
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 109 Checked"


sleep 0.25
# Blacklist 110-111 - WebIron_RBL
	curl -s -H "$UserAgent" https://www.webiron.com/bot_feed/ | grep -q $line
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 110 Checked"

	curl -s -H "$UserAgent" https://www.webiron.com/abuse_feed/ | grep -q $line
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 111 Checked"


sleep 0.25
# Blacklist 112-113 - ZeuS Tracker
	curl -s -H "$UserAgent" https://zeustracker.abuse.ch/blocklist.php?download=badips | grep -q $line
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 112 Checked"

	curl -s -H "$UserAgent" https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist | grep -q $line
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 113 Checked"


sleep 0.25
# Blacklist 114 - Xtream Codes BL
	curl -s -H "$UserAgent" https://xtream-codes.com/blacklist.txt | grep -q $line
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 114 Checked"

sleep 0.25
# Blacklist 115 - Ciarmy
	http://www.ciarmy.com/list/ci-badguys.txt | grep -q $line
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 115 Checked"
	
	
sleep 0.25
# Blacklist 116 - SEI CMU
	https://insights.sei.cmu.edu/cert/mxlist.ips.txt | grep -q $line
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 116 Checked"
	
	
sleep 0.25
# Blacklist 117 - Openphish
	https://openphish.com/feed.txt | grep -q $line
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 117 Checked"
	
	
sleep 0.25
# Blacklist 118 - Maltrail
	https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/mass_scanner.txt | grep -q $line
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 118 Checked"
	
	
sleep 0.25
# Blacklist 119-120 - Firehol
	https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/proxylists.ipset | grep -q $line
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 119 Checked"
	
	
	https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/bitcoin_nodes.ipset | grep -q $line
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 120 Checked"
	
	
sleep 0.25
# Blacklist 121 - Neo23x0
	https://raw.githubusercontent.com/Neo23x0/signature-base/39787aaefa6b70b0be6e7dcdc425b65a716170ca/iocs/otx-c2-iocs.txt | grep -q $line
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 121 Checked"
	
	
sleep 0.25
# Blacklist 122 - BlockedServers
	dig +short A $reverseIP.rbl.blockedservers.com | grep '127.0.0.2'
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 122 Checked"
	
	
	sleep 0.25
# Blacklist 123 - Mail Abuse
	dig +short A $reverseIP.mail-abuse.blacklist.jippg.org | grep '127.0.0.2'
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 123 Checked"
	
	
	sleep 0.25
# Blacklist 124 - Kempt
	dig +short A $reverseIP.dnsbl.kempt.net | grep '127.0.0.2'
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 124 Checked"
	
	
	sleep 0.25
# Blacklist 125 - Konstant
	dig +short A $reverseIP.bl.konstant.no | grep '127.0.0.2'
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 125 Checked"
	
	
	sleep 0.25
# Blacklist 126 - 0Spam
	dig +short A $reverseIP.bl.0spam.org | grep '127.0.0.2'
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 126 Checked"
	
	
	sleep 0.25
# Blacklist 127 - IBM Cobion
	dig +short A $reverseIP.dnsbl.cobion.com | grep '127.0.0.2'
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 127 Checked"
	
	
sleep 0.25
# Blacklist 128-129 - Mailspike
	dig +short A $reverseIP.rep.mailspike.net | grep -q '127.0.0.10\|127.0.0.11\|127.0.0.12\|127.0.0.13\|127.0.0.14'
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 128 Checked"
	
	
	dig +short A $reverseIP.z.mailspike.net | grep '127.0.0.2'
	
	greprc=$?
	
	if [[ $greprc -eq 0 ]] ; then
		(( blacklistCount++ ))
	else
		echo "" >> /dev/null
	fi
	
	echo "Blacklist 129 Checked"



# Add results to report

	echo -e $count'\t'$line'\tBlacklist Count: '$blacklistCount >> $file

# Notify that blacklist check is done
	echo "Blacklist check is done"

# Add spacers to the end of the results
	echo "" >> $file
	echo "==========" >> $file
	echo "" >> $file
	echo "" >> $file

# Increment the line counter and add line spacing
	(( count++ ))
	echo ""
	echo ""

# Add rate-limiting delay for next request
	sleep 2s

done


echo ""
echo "Lookup is completed."
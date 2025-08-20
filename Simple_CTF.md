
This Beginner level CTF

<img width="828" height="362" alt="image" src="https://github.com/user-attachments/assets/3bc73651-c4bb-4239-b555-19ae7e6649de" />

Simple CTF is just that, a beginner-level CTF on TryHackMe that showcases a few of the necessary skills needed for all CTFs to include scanning and enumeration, research, exploitation, and privilege escalation.

Let’s kick off the room with a scan I do on every room, nmap.

<img width="828" height="365" alt="image" src="https://github.com/user-attachments/assets/6fb3b9b8-42a7-4023-8870-ed4b21694ae1" />

From our results, we can see ports 21 (FTP), 80 (HTTP), and 2222 (SSH) are open.

Questions Is:

How many services are running under port 1000?

Answer:2

What is running on the higher port?

Answer:SSH

I was thinking to visit the page robots.txt to find something nothing i got their..

I got something called /openemr-5_0_1_3 in robots.txt when I search it online I got Results like vulnerability report and a CVE:CVE-2018-16795
<img width="828" height="335" alt="image" src="https://github.com/user-attachments/assets/c23ebf50-18ae-4cba-8a7a-4ee00ddabafa" />


Then i tried to run Nmap — script scan to check any vulnerability on system

Starting Nmap 7.95 ( <https://nmap.org> ) at EDT
Nmap scan report for <ip>
Host is up (0.42s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT     STATE SERVICE
21/tcp   open  ftp
80/tcp   open  http
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|_  /robots.txt: Robots file
|_http-csrf: Couldn't find any CSRF vulnerabilities.
| http-slowloris-check: 
|   VULNERABLE:
|   Slowloris DOS attack
|     State: LIKELY VULNERABLE
|     IDs:  CVE:CVE-2007-6750
|       Slowloris tries to keep many connections to the target web server open and hold
|       them open as long as possible.  It accomplishes this by opening connections to
|       the target web server and sending a partial request. By doing so, it starves
|       the http server's resources causing Denial Of Service.
|       
|     Disclosure date: 2009-09-17
Now started gobuster (scan to website to find paths) scan on then i got path to /simple
<img width="828" height="329" alt="image" src="https://github.com/user-attachments/assets/e212c39e-175e-42be-9e98-6a5f063b76c3" />

On that path i got website running
<img width="1100" height="451" alt="image" src="https://github.com/user-attachments/assets/bb313ec6-cbd8-4f80-9ee3-cf5129843511" />

Here we can see this is a default page for something called “CMS Made Simple” and if we look in the bottom corner we can see it is version 2.2.8.

Let’s see if there is anything online about this particular version by simply going to Google and searching “CMS Made Simple 2.2.8 exploit”.

In our results, we see a page on Exploit-DB that matches our search and refers to a SQL injection attack utilizing CVE-2019–9053.
<img width="828" height="291" alt="image" src="https://github.com/user-attachments/assets/91e0b42d-2b08-44fe-a824-0b33a1e3b7b1" />


Now i got exploit on exploit database

<img width="828" height="328" alt="image" src="https://github.com/user-attachments/assets/28648fa9-8519-42a5-894d-2853f47d68be" />

What’s the CVE you’re using against the application?

Answer:CVE-2019–9053

To what kind of vulnerability is the application vulnerable?

Answer:SQLi

Now To Find password of login, we have script to perform let do it then and What is Password…
<img width="817" height="47" alt="image" src="https://github.com/user-attachments/assets/0f41331b-4e77-4572-a44d-21323ecfa6bc" />

Now, let’s run it and see what we get in return.

<img width="480" height="139" alt="image" src="https://github.com/user-attachments/assets/b2315d76-af29-429a-800c-ef1e54e7ad88" />

What’s the password?

secret

Where can you login with the details obtained?

SSH


We got SSH login and let see for user flag
<img width="1100" height="413" alt="image" src="https://github.com/user-attachments/assets/02258426-2ee9-411f-bb9b-2b1858c243c2" />

What’s the user flag?

Answer:G00d j0b, keep up!

Is there any other user in the home directory? What’s its name?

Answer:sunbath
<img width="828" height="92" alt="image" src="https://github.com/user-attachments/assets/a7360905-5e88-4c20-a658-9f6b89daa989" />


On to privileged escalation! First I like to start off with running “sudo -l” to see what my current user can run.

<img width="497" height="59" alt="image" src="https://github.com/user-attachments/assets/07aae540-2c83-4309-8934-0680c9cc792e" />

We can see the user “mitch” can run /usr/bin/vim without a password. With that information, let’s check out GTFOBins and see if we can use that for privesc.

<img width="828" height="527" alt="image" src="https://github.com/user-attachments/assets/cfe4ab2c-6a1c-4eb5-ab15-812c402ca133" />

Recently I learnt about it in the room of Linux Privilege Escalation.

What can you leverage to spawn a privileged shell? Answer: vim
<img width="828" height="174" alt="image" src="https://github.com/user-attachments/assets/e7711749-2268-4506-84a1-c1cab6ee23c9" />
<img width="1100" height="220" alt="image" src="https://github.com/user-attachments/assets/1cfad260-4fa3-4f9a-996a-c1135a2bc585" />


What’s the root flag?
Answer:root.txt
The End!!
Thank you For Reading!!

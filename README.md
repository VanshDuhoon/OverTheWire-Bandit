# OverTheWire Bandit Wargame Solutions

This repository contains my solutions and the commands I used to solve the **Bandit** wargame from OverTheWire.

## ⚠️ Spoiler Warning
If you are playing this game, try solving the levels yourself first!

## Levels Completed: 0 to 20

# OverTheWire Bandit Solutions

## Level 0
* **Goal:** SSH ke through game server se connect karna.
* **Command:** `ssh bandit0@bandit.labs.overthewire.org -p 2220`
* **What I Learnt:** Remote server par login karne ke liye SSH ka use aur port specify karna.

## Level 0 -> Level 1
* **Goal:** Home directory mein `readme` file ko read karke password find karna.
* **Command:** `cat readme`
* **What I Learnt:** File content ko terminal par display karne ke liye `cat` command ka basic use.
* **Password :** `ZjLjTmM6FvvyRnrb2rfNWOZOTa6ip5If`

## Level 1 -> Level 2
* **Goal:** `-` naam wali file ko read karna (jo ki ek special character hai).
* **Command:** `cat ./-`
* **What I Learnt:** Jab file ka naam dash se start ho, toh `./` use karna zaroori hai taaki terminal usse 'option' na samjhe.
* **Password :** `263JGJPfgU6LtdEvgfWU1XP5yac29mFx`

## Level 2 -> Level 3
* **Goal:** Spaces waale file name ko read karna (`spaces in this filename`).
* **Command:** `cat "spaces in this filename"`
* **What I Learnt:** Agar file name mein spaces ho, toh quotes `" "` use karna zaroori hai, ya phir backslash `\` se space ko escape karna padta hai.
* **Password :** `MNk8KNH3Usiio41PRUEoDFPqfxLPlSmx`

## Level 3 -> Level 4
* **Goal:** Hidden directory (`inhere`) se password nikalna.
* **Command:** `ls -la` phir `cat .hidden`
* **What I Learnt:** `ls -a` command hidden files (jo dot `.` se shuru hoti hain) ko dekhne ke liye use hoti hai.
* **Password :** `2WmrDFRmJIq3IPxneAaMGhap0pFhF3NJ`

## Level 4 -> Level 5
* **Goal:** Bohot saari files mein se human-readable file dhundna.
* **Command:** `file ./*`
* **What I Learnt:** `file` command se hum check kar sakte hain ki file ka type kya hai (text, data, ya executable).
* **Password :** `4oQYVPkxZOOEOO5pTW81FB8j8lxXGUQw`

## Level 5 -> Level 6
* **Goal:** Specific properties waali file dhundna (size, user, group).
* **Command:** `find . -type f -size 1033c ! -executable`
* **What I Learnt:** `find` command ke filters (size, type) ka use karke specific files search karna.
* **Password :** `HWasnPhtq9AVKe0dmk45nxy20cvUa6EG`

## Level 6 -> Level 7
* **Goal:** Pura system mein file search karna using user/group name.
* **Command:** `find / -user bandit7 -group bandit6 -size 33c 2>/dev/null`
* **What I Learnt:** `2>/dev/null` ka use karke "Permission Denied" waale errors ko hide karna.
* **Password :** `morbNTDkSW6jIlUc0ymOdMaLnOlFVAaj`

## Level 7 -> Level 8
* **Goal:** `data.txt` mein 'millionth' word ke side wala password nikalna.
* **Command:** `grep "millionth" data.txt`
* **What I Learnt:** `grep` command se file ke andar specific text search karna.
* **Password :** `dfwvzFQi4mU0wfNbFOe9RoWskMLg7eEc`

## Level 8 -> Level 9
* **Goal:** Aisi line dhundna jo sirf ek baar aayi ho.
* **Command:** `sort data.txt | uniq -u`
* **What I Learnt:** `uniq` command sirf sorted files par kaam karti hai, isliye pehle `sort` karna padta hai.
* **Password :** `4CKMh1JI91bUIZZPXDqGanal4xvAg0JM`

## Level 9 -> Level 10
* **Goal:** Binary file mein se human-readable strings nikalna.
* **Command:** `strings data.txt | grep "=="`
* **What I Learnt:** `strings` command binary files mein se text extract karne ke liye best hai.
* **Password :** `FGUW5ilLVJrxX9kMYMmlN4MgbpfMiqey`

## Level 10 -> Level 11
* **Goal:** Base64 encoded data ko decode karna.
* **Command:** `base64 -d data.txt`
* **What I Learnt:** Base64 encoding/decoding ka basic concept.
* **Password :** `dtR173fZKb0RRsDFSGsg2RWnpNVj3qRr`

## Level 11 -> Level 12
* **Goal:** ROT13 cipher (text rotation) ko decode karna.
* **Command:** `cat data.txt | tr 'A-Za-z' 'N-ZA-Mn-za-m'`
* **What I Learnt:** `tr` (translate) command ka use karke characters ko replace karna.
* **Password :** `7x16WNeHIi5YkIhWsfFIqoognUTyj9Q4`

## Level 12 -> Level 13
* **Goal:** Compressed files (Hexdump, Gzip, Bzip2, Tar) ko baar-baar decompress karna.
* **Command:** `xxd -r`, `gzip -d`, `bzip2 -d`, `tar -xf`
* **What I Learnt:** Ek file ke andar multiple layers of compression ho sakti hain. `file` command se har step par type check karna zaroori hai.
* **Password :** `FO5dwFsc0cbaIiH0h8J2eUks2vdTDwAn`


## Level 13 → 14: SSH Private Keys & Permissions

### Objective
Login to the next level using a private SSH key (`sshkey.private`) found in the home directory, rather than a password.

### Key Learnings
1.  **SSH Identity Files:** Instead of a password, SSH can use a private key file for authentication using the `-i` flag.
2.  **Permission Security:** SSH clients will reject private keys if they are too "open" (readable by others). Keys must be restricted to the owner only.
3.  **Localhost Restrictions:** The Bandit server blocks SSH connections to the hostname `localhost` to force the use of specific IP addresses.

### Challenges & Solutions
* **Challenge:** "Permission Denied" when trying to use the key.
    * **Solution:** The key file permissions were too open (e.g., 644). I fixed this by running `chmod 600 sshkey.private` (read/write for owner only).
* **Challenge:** "System resources" error when connecting to `localhost`.
    * **Solution:** Bypassed the restriction by using the loopback IP `127.0.0.1` explicitly.

* **At last:** Nothing worked from above , to solve this level i used nano to make key again for that i used cat to cat `sshkey.private` .

### Commands Used
```bash
# Setting secure permissions
chmod 600 sshkey.private

# Logging in via localhost using the key
ssh -i sshkey.private bandit14@127.0.0.1 -p 2220
```


```

---

##  Level 14 → 15: Netcat & Port Submission

### Objective
Submit the current level's password to port `30000` on the local machine to retrieve the password for the next level.

### Key Learnings
* **Netcat (`nc`):** A utility for reading from and writing to network connections (TCP/UDP).
* **Piping (`|`):** Used to pass the output of one command (reading the password file) directly as input to another command (sending it to the network port).

### Solution Process
I used `cat` to read the password file and piped it into `nc` connecting to localhost on port 30000.

### Commands Used
```bash
cat /etc/bandit_pass/bandit14 | nc localhost 30000
```
---

##  Level 15 → 16: SSL Encryption & OpenSSL

### Objective
Submit the current level's password to port `30001` on localhost using SSL encryption.

### Key Learnings
* **SSL/TLS:** Unlike standard Netcat (`nc`), which sends cleartext, many secure services require an encrypted connection.
* **OpenSSL:** A command-line toolkit for the TLS and SSL protocols.

### Commands Used
```bash
# Connect using the SSL client to the specified port
openssl s_client -connect localhost:30001 -quiet
(After running the command, I pasted the Level 15 password to receive the credential for Level 16.)
```
--- 

## Level 16 → 17: Port Scanning & RSA Keys
### Objective
Find a service listening on a port between 31000 and 32000 that speaks SSL, retrieve an RSA private key, and use it to log in.

### Key Learnings
* **Port Scanning (nmap):** Used to discover open ports on a server.

* **RSA Private Keys: Using a file**-based key for SSH authentication instead of a password.

### Solution Process
Scanned the port range to find open ports:
```bash

nmap -p 31000-32000 localhost
Identified the correct port (running SSL) and connected:
```

```bash

openssl s_client -connect localhost:31790 -quiet
Saved the RSA Private Key response to a file (bandit17.key), fixed permissions, and logged in.
``` 
### Commands Used
``` bash

# Create and secure the key file
nano bandit17.key
chmod 600 bandit17.key

# Login using the key
ssh -i bandit17.key bandit17@bandit.labs.overthewire.org -p 2220
``` 

## Level 17 → 18: File Comparison (Diff)
### Objective
Find the password located in passwords.new. The file is identical to passwords.old except for one changed line.

### Key Learnings
* **diff**: A tool that compares files line-by-line and outputs the differences.

### Commands Used
```bash

diff passwords.old passwords.new
``` 

## Level 18 → 19: SSH Command Execution (Shell Trap)
### Objective
Log in to Bandit 18, where the shell is configured to immediately log you out ("Byebye!").

### Key Learnings
* **SSH Command Execution**: You can pass a command to SSH to run before the remote shell starts (and potentially kicks you out).

* **Solution Process**
Instead of logging in interactively, I appended the command I wanted to run to the SSH connection string.

### Commands Used
```bash

ssh bandit18@bandit.labs.overthewire.org -p 2220 "cat readme"
```
## Level 19 → 20: SUID & Privilege Escalation
### Objective
Read the password file /etc/bandit_pass/bandit20. Access is denied for the current user, but a setuid binary is provided.

### Key Learnings
* **SUID (Set User ID)**: A permission bit that allows a user to execute a file with the permissions of the file's owner (in this case, Bandit 20).

* **Privilege Escalation:** Using a tool with higher privileges to perform actions (like reading a restricted file) that the current user cannot do.

### Commands Used
``` bash

# Run the binary to execute 'cat' with Bandit 20's permissions
./bandit20-do cat /etc/bandit_pass/bandit20
```

---

## Level 20 → 21: Networking (Server-Client Interaction)

### Objective
Receive the password for the next level by setting up a listener on a specific port and forcing a setuid binary (`suconnect`) to connect to it.

### Key Learnings
* **Client-Server Architecture:** Understanding that for a connection to happen, one side must "Listen" (Server) and the other must "Connect" (Client).
* **Netcat (`nc`) Listener:** Using `nc -l` to open a port and wait for incoming data.
* **Job Control (`&`):** Running a command in the background so the terminal remains usable for a second command.

### Solution Process
1.  **Set up a Listener:** I used Netcat to listen on port `4444` in the background.
2.  **Trigger the Client:** I ran the `suconnect` binary, instructing it to connect to my listener.
3.  **Authentication:** Once connected, I sent the current password to the binary, which responded with the new password.

### Commands Used
```bash
# Option A: Using two terminal windows
# Terminal 1 (Listener)
nc -l -p 4444

# Terminal 2 (Client Trigger)
./suconnect 4444

```

## Option B: Using background jobs (&) in one window
nc -l -p 4444 &
./suconnect 4444
## (Then paste the current password and hit Enter )

---

##  Level 21 → 22: Cron Jobs & Automation

### Objective
The password is being moved automatically by a "Cron Job" running in the background. The goal is to identify the schedule and find the target file.

### Key Learnings
* **Cron (`/etc/cron.d/`):** The standard location for system scheduled tasks.
* **Analyzing Scripts:** Reading shell scripts (`.sh`) to understand what the system is doing automatically.

### Solution Process
1.  Checked `/etc/cron.d/` and found a job named `cronjob_bandit22`.
2.  Read the job file, which pointed to a script: `/usr/bin/cronjob_bandit22.sh`.
3.  Analyzed the script and found it copies the password to a temp file in `/tmp/`.
4.  Read that temp file to get the password.

### Commands Used
```bash
ls -la /etc/cron.d/
cat /usr/bin/cronjob_bandit22.sh
cat /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv  # (Filename varies)
``` 

## Level 22 → 23: Script Logic & Hashing
### ojective
A script copies the password to a filename that changes based on the username. We need to determine what the filename would be for the next user (bandit23).

### Key Learnings
Reverse Engineering Logic: Reading code to understand how a filename is generated.

MD5 Hashing (md5sum): Converting a string of text into a unique fingerprint.

Command Substitution ($()): How scripts use the output of one command inside another.

### Solution Process
Found the script for the next level (cronjob_bandit23).

Noticed it uses echo I am user $myname | md5sum to create the filename.

Manually ran that command, replacing $myname with bandit23.

Used the resulting hash to read the password file in /tmp/.

### Commands Used

```bash 
# Calculate the target filename manually
echo I am user bandit23 | md5sum | cut -d ' ' -f 1

# Read the file using the hash we just found
cat /tmp/8ca319486bfbbc3663ea0fbe81326349
``` 

## Level 23 → 24: Shell Script Injection
### Objective
The system runs any script found in /var/spool/bandit24/foo. We need to write a script to steal the password and place it there.

### Key Learnings
Writing Shell Scripts: Creating a simple .sh file to execute commands.

* **Permissions (chmod):** Making a script "executable" so the system can run it, and "writable" so we can edit it.

* **Redirection (>):** sending output to a file instead of the screen.

### Solution Process
Created a temporary workspace: mkdir /tmp/mywork.

Wrote a script that reads the password and saves it to a file in my folder.

Made the script executable (chmod 777).

Copied the script to the "trap" folder (/var/spool/bandit24/foo).

Waited for the Cron job to trigger it.

### Commands Used

```bash
# Inside myscript.sh:
#!/bin/bash
cat /etc/bandit_pass/bandit24 > /tmp/mywork/pass.txt
chmod 666 /tmp/mywork/pass.txt

# Setup commands:
chmod 777 myscript.sh
chmod 777 /tmp/mywork
cp myscript.sh /var/spool/bandit24/foo/
```



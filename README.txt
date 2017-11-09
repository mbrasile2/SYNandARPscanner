Name: Michael Brasile
ID: 109712327
CSE 331 HW 3


---------------------------------------------- PART 1 ----------------------------------------------
The packages I used for this part:

scapy to ping host and perform syn scan (http://scapy.readthedocs.io/en/latest/introduction.html)
netaddr to parse subnets (http://netaddr.readthedocs.io/en/latest/)

This is how my program runs:

Check if the provided IP address can be reached by sending a ping request (it will iterate through 
the whole subnet after performing the probing on the previous IP). If the host is down, the program 
prints the error and exits. If the host successfully connects, it iterates through a list of ports
with a SYN packet to see if it's open. If it's open, the program sends a RST packet to terminate the
connection and then a python socket connects to the host to perform banner grabbing. The dummy request
is just an HTTP GET request. It then prints that specified port that is open and the response. Here is
an example.

First I run the following command:

python synprobe.py -p 1-100 www.hackthissite.org

So this probes port number 1 to 100 on the domain "www.hackthissite.org". Here is the result:



Port 22: open. Response: SSH-2.0-OpenSSH_5.8p1_hpn13v10 FreeBSD-20110102

Port 80: open. Response: HTTP/1.1 200 OK
Date: Thu, 09 Nov 2017 21:54:06 GMT
Content-Type: text/html
Transfer-Encoding: chunked
Connection: keep-alive
Set-Cookie: PHPSESSID=0as66722q1qn8v9kbh60i170p1; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
Pragma: no-cache
Server: HackThisSite Load Balancer
Strict-Transport-Security: max-age=31536000; includeSubdomains; preload
X-Content-Type-Options: nosniff

ec9
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">

<head>
  <title>Hack This Site!</title>
  <meta name="verify-v1" content="s/YXn7eQrMBoF9PL5jLJDiWpAxEXpJzE9JLg/zM4C2Y=" />
  <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
  <meta name="author" content="HackThisSite.org Crew." />
  <meta name="description" content="HackThisSite! is a legal and safe network security resource wher


According to the ouput, port 22(ssh) and port 80(HTTP) are open and the response is printed accordingly.
In the event the port is closed or the SYN request times out, it just moves on to the next port.



---------------------------------------------- PART 2 ----------------------------------------------

The packages I used for this part:

scapy (http://scapy.readthedocs.io/en/latest/introduction.html) - For packet sniffing
netifaces (https://pypi.python.org/pypi/netifaces) - For getting the IP address of a given interface

This is how my program runs:

I get the computers IP address using netifaces and get the address for the subnet. Then, I perform a
scan of the arp cache for that interface using srp() and store each entry into a global dict.
The format is {IP : MAC}. After that, I perform a passive arp scan by using sniff() on that interface and 
setting a prn function that runs on a captured packet. If the IP and MAC address of the captured packet
don't correspond to an entry in the arp_cache dict, it prints a warning to the user. Here is an example
of it in action.


I currently run vmware fusion on my Mac with two running VM's: Kali Linux and Metasploitable. These 
VM's are put in a separate interface on MAC OS as vmnet8. This is what I ran:

python arpwatch.py -i vmnet8


Here are the following entries in the cache:

------INITIAL ARPCACHE IP/MAC ADDRESSES------
192.168.110.171		:		00:0c:29:ed:5f:52 <-- This is Metasploitable
192.168.110.174		:		00:0c:29:c7:1f:d4 <-- This is Kali Linux
192.168.110.254		:		00:50:56:e5:04:06 <-- MAC OS


On Kali Linux, I performed the following command:

sudo arpspoof -i eth0 192.168.110.171


This changes the MAC address of Metaploitable to Kali Linux and targets every host in the subnet.
As expected, arpwatch picked up this sus behavior and printed the following warning:

192.168.110.171 CHANGED FROM 00:0c:29:ed:5f:52 TO 00:0c:29:c7:1f:d4


Since arpspoof is constantly sending is-at operations on the ARP cache, this warning repeats every time
Kali Linux sends a packet. 
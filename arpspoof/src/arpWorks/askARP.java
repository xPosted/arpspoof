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
	
	public byte[] ask(String ip,NetworkInterface dev) throws IOException{
		
		NetworkInterface[] devices = JpcapCaptor.getDeviceList();
		
		 capt = JpcapCaptor.openDevice(dev, 32768, true, 0);
		ARPPacket req = new ARPPacket();
		req.hlen=6;
		req.plen=4;
		req.hardtype = ARPPacket.HARDTYPE_ETHER;
		req.prototype = ARPPacket.PROTOTYPE_IP;
		req.operation = ARPPacket.ARP_REQUEST;
		req.sender_hardaddr=dev.mac_address;
		
		req.sender_protoaddr=dev.addresses[0].address.getAddress();
		req.target_hardaddr = new byte[] {(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff};
		
		req.target_protoaddr=InetAddress.getByName(ip).getAddress();
		EthernetPacket ether = new EthernetPacket();
		ether.dst_mac=new byte[] {(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff};
		ether.src_mac=dev.mac_address;     //devices[dev].mac_address;
		ether.frametype=EthernetPacket.ETHERTYPE_ARP;
		req.datalink=ether;
		

		JpcapSender sender =JpcapSender.openDevice(dev);
			System.out.println("\t"+req);
		capt.setFilter("arp and src host "+ip,true);
		sender.sendPacket(req);
		
		capt.loopPacket(-1, this);
		return mac;
		
	}

	@Override
	public void receivePacket(Packet arg0) {
		
		ARPPacket arp = (ARPPacket) arg0;
		if ((arp.operation==ARPPacket.ARP_REPLY)) {
				System.out.println("\t"+arp);
			mac=arp.sender_hardaddr;
			capt.breakLoop();
			
		}
	}

}








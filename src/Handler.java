import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;


import net.sourceforge.jpcap.capture.*;
import net.sourceforge.jpcap.net.*;

public class Handler implements PacketListener{
	
	private List<ARPCacheCell> arpTable = new ArrayList<ARPCacheCell>();
	private int debug = 0;
	
	@Override
	public void packetArrived(Packet packet) {
		
		checkARPSpoof();
		
		try {
			
			if (packet instanceof EthernetPacket) {
				
				System.out.println(ethernet((EthernetPacket)packet));
				
				if (packet instanceof ARPPacket) {
					
					addToARPTable((ARPPacket) packet);
					System.out.println(arp((ARPPacket) packet));
					
				} else if (packet instanceof IPPacket) {
					
					System.out.println(ip((IPPacket)packet));
					
					if (packet instanceof ICMPPacket){
						
						System.out.println(icmp((ICMPPacket)packet));
						
					} else if (packet instanceof TCPPacket) {
						
						System.out.println(transport((TCPPacket)packet));
						
					} else if (packet instanceof UDPPacket) {
						
						System.out.println(transport((UDPPacket)packet));
						
					}
				}
			}
			
			for(int i = 0; i < 20; i++) {
				System.out.print("-");
			}
			
		} catch (Exception e) {
			System.out.println("Failed Capture");
		}
	}
	
	public String ethernet (EthernetPacket packet) {
		int headerLgth = packet.getEthernetHeaderLength();
		String srcMac = packet.getSourceHwAddress(), destMac = packet.getDestinationHwAddress();
		
		return "\nEthernet: \nHeader Length: " + headerLgth + "\nSrc Mac Address: " + srcMac + "\tDest Mac Address: " + destMac;
		
	}
	
	public String arp (ARPPacket packet) {
		String srcMac = packet.getSourceHwAddress(), destMac = packet.getDestinationHwAddress(), 
				srcIP = packet.getSourceProtoAddress(), destIP = packet.getDestinationProtoAddress();
		
		return "\nARP: " + "\nSrc IP Address: " + srcIP + "\tDest IP Address: " + destIP +
				"\nSrc MAC Address: " + srcMac + "\tDest MAC Address: " + destMac;
	}
	
	public void addToARPTable (ARPPacket packet) {
		String assocIP = packet.getSourceProtoAddress();
		String mac = packet.getSourceHwAddress();
		boolean isExisting = false;
				
		if (!arpTable.isEmpty()) {
			for(ARPCacheCell cell : arpTable) {
				if (isExisting) {
					break;
				}
								
				if (cell.getIP().equals(assocIP) && cell.getMac().equals(mac)) {
					isExisting = true;
				}
			}
			
			if (!isExisting) {
				arpTable.add(new ARPCacheCell(mac, assocIP));
			}
		} else {
			arpTable.add(new ARPCacheCell(mac, assocIP));
		}
	}
	
	public String ip (IPPacket packet) {
		String srcIP = packet.getSourceAddress(), destIP = packet.getDestinationAddress();
		int checksum = packet.getChecksum(), headerLgth = packet.getIPHeaderLength();
		return "\nIP: \nHeaderLength: " + headerLgth + "\nSrc IP Address: " + srcIP + "\tDest IP Address: " + destIP
				+ "\nChecksum: " + checksum;
	}
	
	public String icmp (ICMPPacket packet) {
		String srcIP = packet.getSourceAddress(), destIP = packet.getDestinationAddress();
		int type = packet.getTypeOfService();
		
		return "\nICMP: " + "\tType: " + type +
				"\nSrc IP Address: " + srcIP + "\tDest IP Address: " + destIP;
	}
	
	public String transport (TCPPacket packet) {
		
		long ack, seq;
		int destPort, srcPort, windowSize, urgPointer;
		boolean ackf, finf, pshf, rstf, synf, urgf;
		
		int headerLgth = packet.getHeaderLength();
		
		ack = packet.getAcknowledgementNumber();
		seq = packet.getSequenceNumber();
		
		srcPort = packet.getSourcePort();
		destPort = packet.getDestinationPort();
		windowSize = packet.getWindowSize();
		urgPointer = packet.getUrgentPointer();
		
		synf = packet.isSyn();
		ackf = packet.isAck();
		finf = packet.isFin();
		pshf = packet.isPsh();
		rstf = packet.isRst();
		urgf = packet.isUrg();
		
		return "\nTCP: \nHeader Length: " + headerLgth + "\nSeq: " + seq + "\tAck: " + ack + "\nSrc Port: " + srcPort + "\tDest Port: " + destPort
				+ "\nWindow Size: " + windowSize + "\tUrgent Pointer: " + urgPointer + "\nFlags: \tSyn: " + synf + "\tAck: " + ackf 
				+ "\tfinf: " + finf + "\tpshf: " + pshf + "\trstf: " + rstf + "\turgf: " + urgf;
	}
	
	public String transport (UDPPacket packet) {
		int destPort = packet.getDestinationPort(), srcPort = packet.getSourcePort(), headerLgth = packet.getChecksum();
		return "\nUDP: \nHeader Length: " + headerLgth + "\nSrc Port: " + srcPort + "\tDestPort: " + destPort;
	}
	
	public void checkARPSpoof() {
		System.out.println("\n=========================ARP TABLE========================\n");
		
		for(ARPCacheCell cell: arpTable) {
			System.out.println(cell.getIP() + " " + cell.getMac());
		}
		
		System.out.println("\n=========================ARP TABLE========================\n");
		
		for(ARPCacheCell cell: arpTable) {
			String ip = cell.getIP(), mac = cell.getMac();
			
			for(ARPCacheCell compCell: arpTable) {
				String cIp = compCell.getIP(), cMac = compCell.getMac();
				
				if (!(ip.equals(cIp) && mac.equals(cMac))) {
					if (ip.equals(cIp) && !mac.equals(cMac)) {
						System.out.println("\n===========================\nWARNING: ARP SPOOFING DETECTED!\n===========================\n");
					}
				}
				
				
			}
		}
	}
	
}
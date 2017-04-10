import java.util.Scanner;

import net.sourceforge.jpcap.capture.*;
import net.sourceforge.jpcap.net.Packet;

public class Sniffer {
	
	private PacketCapture pcap;
	
	public Sniffer() throws CaptureDeviceLookupException, CaptureDeviceOpenException, CapturePacketException {
		pcap = new PacketCapture();
		
		System.out.println("\nList of devices: ");
		String[] devices = pcap.lookupDevices();
		
		System.out.println("Option if the devices above do not work: ");
		
		try {
			System.out.println(pcap.findDevice());
		} catch (CaptureDeviceNotFoundException e) {
			System.out.println("No recommended devices.");
		}
		
		System.out.print("\nEnter a device to capture from or 'rec' to use the recommended option: ");
		
		Scanner devicePrompt = new Scanner(System.in);
		String device = null; 
		boolean waiting = true;
		while (waiting) {
			device = devicePrompt.nextLine();
			device = validate(device, devices);
			
			if (device != null) {
				waiting = false;
			}
		}
		
		devicePrompt.close();
		System.out.println("\nCapturing on: " + device);
		
		pcap.open(device, true);
		pcap.addPacketListener(new Handler());
		pcap.capture(-1);
	}
	
	public String validate(String device, String[] devices) throws CaptureDeviceLookupException {
		if (device.equals("rec")) {
			try {
				if(pcap.findDevice().indexOf('\n') != -1) {
					device = pcap.findDevice().substring(0, pcap.findDevice().indexOf('\n'));
					return device;
				} else {
					device = pcap.findDevice();
					return device;
				}
				
			} catch (CaptureDeviceNotFoundException e) {
				e.printStackTrace();
			}
		} else if (device.length() > 0) {
			for (String i: devices) {
				if (device.equals(i)) {
					return device;
				}
			}
		}
		
		System.out.println("Not a valid device. Try again.");
		
		return null;
	}
	
	public static void main(String[] args) {
		
		for(int i = 0; i < 3; i++) {

			for(int j = 0; j < 70; j++) {
				System.out.print("=");
			}
			
			System.out.print("\n");
		}

		System.out.println("\nA packet sniffer created by Edmund Do using JPcap \n");

		for(int i = 0; i < 3; i++) {

			for(int j = 0; j < 70; j++) {
				System.out.print("=");
			}
			System.out.print("\n");
		}
		
		try {
			Sniffer sniffer = new Sniffer();
		} catch (Exception e) {
			System.out.println("Error creating sniffer for " + e.getMessage());
		}
		
	}

}

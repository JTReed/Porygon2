package edu.wisc.cs.sdn.sr;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import com.sun.corba.se.impl.protocol.giopmsgheaders.TargetAddress;

import edu.wisc.cs.sdn.sr.vns.VNSComm;

import net.floodlightcontroller.packet.*;
import net.floodlightcontroller.util.MACAddress;

/**
 * @author Aaron Gember-Jacobson
 */
public class Router {
	/** User under which the router is running */
	private String user;

	/** Hostname for the router */
	private String host;

	/** Template name for the router; null if no template */
	private String template;

	/** Topology ID for the router */
	private short topo;

	/** List of the router's interfaces; maps interface name's to interfaces */
	private Map<String, Iface> interfaces;

	/** Routing table for the router */
	private RouteTable routeTable;

	/** ARP cache for the router */
	private ArpCache arpCache;

	/**
	 * PCAP dump file for logging all packets sent/received by the router; null
	 * if packets should not be logged
	 */
	private DumpFile logfile;

	/** Virtual Network Simulator communication manager for the router */
	private VNSComm vnsComm;

	/** RIP subsystem */
	private RIP rip;

	/**
	 * Creates a router for a specific topology, host, and user.
	 * 
	 * @param topo
	 *            topology ID for the router
	 * @param host
	 *            hostname for the router
	 * @param user
	 *            user under which the router is running
	 * @param template
	 *            template name for the router; null if no template
	 */
	public Router(short topo, String host, String user, String template) {
		this.topo = topo;
		this.host = host;
		this.setUser(user);
		this.template = template;
		this.logfile = null;
		this.interfaces = new HashMap<String, Iface>();
		this.routeTable = new RouteTable();
		this.arpCache = new ArpCache(this);
		this.vnsComm = null;
		this.rip = new RIP(this);
	}

	public void init() {
		this.rip.init();
	}

	/**
	 * @param logfile
	 *            PCAP dump file for logging all packets sent/received by the
	 *            router; null if packets should not be logged
	 */
	public void setLogFile(DumpFile logfile) {
		this.logfile = logfile;
	}

	/**
	 * @return PCAP dump file for logging all packets sent/received by the
	 *         router; null if packets should not be logged
	 */
	public DumpFile getLogFile() {
		return this.logfile;
	}

	/**
	 * @param template
	 *            template name for the router; null if no template
	 */
	public void setTemplate(String template) {
		this.template = template;
	}

	/**
	 * @return template template name for the router; null if no template
	 */
	public String getTemplate() {
		return this.template;
	}

	/**
	 * @param user
	 *            user under which the router is running; if null, use current
	 *            system user
	 */
	public void setUser(String user) {
		if (null == user) {
			this.user = System.getProperty("user.name");
		} else {
			this.user = user;
		}
	}

	/**
	 * @return user under which the router is running
	 */
	public String getUser() {
		return this.user;
	}

	/**
	 * @return hostname for the router
	 */
	public String getHost() {
		return this.host;
	}

	/**
	 * @return topology ID for the router
	 */
	public short getTopo() {
		return this.topo;
	}

	/**
	 * @return routing table for the router
	 */
	public RouteTable getRouteTable() {
		return this.routeTable;
	}

	/**
	 * @return list of the router's interfaces; maps interface name's to
	 *         interfaces
	 */
	public Map<String, Iface> getInterfaces() {
		return this.interfaces;
	}

	/**
	 * @param vnsComm
	 *            Virtual Network System communication manager for the router
	 */
	public void setVNSComm(VNSComm vnsComm) {
		this.vnsComm = vnsComm;
	}

	/**
	 * Close the PCAP dump file for the router, if logging is enabled.
	 */
	public void destroy() {
		if (logfile != null) {
			this.logfile.close();
		}
	}

	/**
	 * Load a new routing table from a file.
	 * 
	 * @param routeTableFile
	 *            the name of the file containing the routing table
	 */
	public void loadRouteTable(String routeTableFile) {
		if (!routeTable.load(routeTableFile)) {
			System.err.println("Error setting up routing table from file "
					+ routeTableFile);
			System.exit(1);
		}

		System.out.println("Loading routing table");
		System.out.println("---------------------------------------------");
		System.out.print(this.routeTable.toString());
		System.out.println("---------------------------------------------");
	}

	/**
	 * Add an interface to the router.
	 * 
	 * @param ifaceName
	 *            the name of the interface
	 */
	public Iface addInterface(String ifaceName) {
		Iface iface = new Iface(ifaceName);
		this.interfaces.put(ifaceName, iface);
		return iface;
	}

	/**
	 * Gets an interface on the router by the interface's name.
	 * 
	 * @param ifaceName
	 *            name of the desired interface
	 * @return requested interface; null if no interface with the given name
	 *         exists
	 */
	public Iface getInterface(String ifaceName) {
		return this.interfaces.get(ifaceName);
	}

	public boolean checkChecksum(IPv4 packet) {
		if (packet.getProtocol() == IPv4.PROTOCOL_ICMP) {
			short checksum = packet.getChecksum();
			packet.setChecksum((short) 0);
			packet.serialize();
			return (checksum == packet.getChecksum());
		}

		short checksum = packet.getChecksum();
		packet.setChecksum((short) 0);
		packet.serialize();
		return (checksum == packet.getChecksum());
	}

	/**
	 * Send an Ethernet packet out a specific interface.
	 * 
	 * @param etherPacket
	 *            an Ethernet packet with all fields, encapsulated headers, and
	 *            payloads completed
	 * @param iface
	 *            interface on which to send the packet
	 * @return true if the packet was sent successfully, otherwise false
	 */
	public boolean sendPacket(Ethernet etherPacket, Iface iface) {
		return this.vnsComm.sendPacket(etherPacket, iface.getName());
	}

	// TODO -- FOR DATA PLANE
	/**
	 * Handle an Ethernet packet received on a specific interface.
	 * 
	 * @param etherPacket
	 *            the Ethernet packet that was received
	 * @param inIface
	 *            the interface on which the packet was received
	 */
	public void handlePacket(Ethernet etherPacket, Iface inIface) {
		System.out.println("*** -> Received packet: "
				+ etherPacket.toString().replace("\n", "\n\t"));

		/********************************************************************/
		/*
		 * TODO: Handle packets + either + 1. forward the packet to another
		 * interface + If the frame contains an IP packet that is not destined
		 * for one of our interfaces: + Check the packet has the correct
		 * checksum. + Decrement the TTL by 1. + Find out which entry in the
		 * routing table + has the longest prefix match with the destination IP
		 * address. + Check the ARP cache for the next-hop MAC address
		 * corresponding + to the next-hop IP. If it's there, send the packet. +
		 * Otherwise, call waitForArp(...) function in the ARPCache + class to
		 * send an ARP request for the next-hop IP, + and add the packet to the
		 * queue of packets waiting on this ARP request. + If error occurs: + If
		 * an error occurs in any of the above steps, + you will have to send an
		 * ICMP message back + to the sender notifying them of an error. + 2.
		 * pass the packet to the ARP or RIP subsystems + See: Invoking Control
		 * Plane Code & Responding to Pings + 3. respond with an ICMP packet +
		 * See: Iase ARP.OP_REQUEST:
				System.out.println( "handlign ARP request" );
				// Check if request is for one of my interfaces
				if (targetIp == inIface.getIpAddress()) {
					this.arpCache.sendArpReply(etherPacket, inIface);
				}
				break;
			case ARP.OP_REPLY:
				System.out.println( "handlign ARP reply from " + Util.intToDottedDecimal( Integer.parseInt( arpPacket.getSenderProtocolAddress().toString() ) ) );
				// Check if reply is for one of my interfaces
				if (targetIp != inIface.getIpAddress()) {
					break;
				}
	
				// Update ARP cache with contents of ARP reply
				ArpRequest request = this.arpCache.insert(
						new MACAddress(arpPacket.getTargetHardwareAddress()),
						targetIp);
	
				// Process pending ARP request entry, if there is one
				if (request != null) {
					for (Ethernet packet : request.getWaitingPackets()) {
						if (nextHop( packet )){
							arpCache.removeFromRequests( request );
						}
					}
				}CMP on wbpge + SEE PART THREE on WEBSITE under "Router.java" +
		 * SEE sendPacket() to send +
		 */

		/********************************************************************/
		if (etherPacket.getEtherType() == Ethernet.TYPE_ARP) {
			System.out
					.println("received ARP packet, calling handleArpPacket()");
			handleArpPacket(etherPacket, inIface);
		} else if (etherPacket.getEtherType() == Ethernet.TYPE_IPv4) {
			System.out
					.println("received IP packet, calling calling handleIpPacket()");
			handleIPPacket(etherPacket, inIface);
		} else {
			System.out.println("packet is neither ARP nor IP");
		}
	}

	/**
	 * Handle an ARP packet received on a specific interface.
	 * 
	 * @param etherPacket
	 *            the complete ARP packet that was received
	 * @param inIface
	 *            the interface on which the packet was received
	 */
	private void handleArpPacket(Ethernet etherPacket, Iface inIface) {
		// Make sure it's an ARP packet
		System.out.println("handling ARP packet");
		if (etherPacket.getEtherType() != Ethernet.TYPE_ARP) {
			return;
		}

		// Get ARP header
		ARP arpPacket = (ARP) etherPacket.getPayload();
		int targetIp = ByteBuffer.wrap(arpPacket.getTargetProtocolAddress()).getInt();

		switch (arpPacket.getOpCode()) {
			case ARP.OP_REQUEST:
				System.out.println( "handling ARP request" );
				// Check if request is for one of my interfaces
				if (targetIp == inIface.getIpAddress()) {
					this.arpCache.sendArpReply(etherPacket, inIface);
				}
				break;
			case ARP.OP_REPLY:
				System.out.println("handling ARP Reply");
				// Check if reply is for one of my interfaces
				if (targetIp != inIface.getIpAddress()) {
					break;
				}
	
				
				// Update ARP cache with contents of ARP reply
				int senderIp = ByteBuffer.wrap( arpPacket.getSenderProtocolAddress()).getInt();
				ArpRequest request = this.arpCache.insert(new MACAddress(arpPacket.getSenderHardwareAddress()), senderIp);
				
				// Process pending ARP request entry, if there is one
				if (request != null) {
					for (Ethernet packet : request.getWaitingPackets()) {
						if (nextHop( packet )){
							arpCache.removeFromRequests( request );
						}
					}
				}
				else {
					System.out.println( "request is null" );
				}
				break;
		}
	}

	/**
	 * Handle an IP packet received on a specific interface.
	 * 
	 * @param etherPacket
	 *            the complete ARP p byteacket that was received
	 * @param inIface
	 *            the interface on which the packet was received
	 */
	private void handleIPPacket(Ethernet etherPacket, Iface inIface) {
		IPv4 ipPacket = (IPv4) etherPacket.getPayload();
		int targetAddress = ipPacket.getDestinationAddress();
		boolean isOnInterface = false;

		if (!checkChecksum(ipPacket)) {
			System.out.println("Checksum does not match");
			return;
		}

		// If TTL is 0, then we need to panic!
		ipPacket.setTtl((byte) (ipPacket.getTtl() - 1));
		if ((int) ipPacket.getTtl() == 0) {
			// outatime!
			System.out.println("TTL is 0");
			// TODO: ICMP.TYPE_TIME_EXCEEDED
			return;
		}

		// Check if this packet is on one of our interfaces
		for (Map.Entry<String, Iface> interfaceEntry : getInterfaces().entrySet()) {
			if ( targetAddress == interfaceEntry.getValue().getIpAddress()) {
				isOnInterface = true;
				break;
			}
		}

		if (isOnInterface) {
			// congratulations, this packet has arrived at its destination!
			System.out.println("Packet sees the interface");
			byte ipProtocol = ipPacket.getProtocol();
			int port;
			switch (ipProtocol) {
			case IPv4.PROTOCOL_ICMP:
				System.out.println("ICMP packet received");

				ICMP icmpPacket = (ICMP) ipPacket.getPayload();
				// TODO check if checksum is valid!
				if (checkChecksum(ipPacket)) {
					System.out.println("icmp checksum is a go");
				} else {
					System.out
							.println("icmp checksums do not match - something messed up");
				}
				// TODO: ICMP.ECHO_REPLY
				sendICMPReply( etherPacket, inIface, ICMP.TYPE_ECHO_REQUEST, ICMP.CODE_ECHO_REQUEST );
				break;
			case IPv4.PROTOCOL_TCP:
				TCP tcpPacket = (TCP) ipPacket.getPayload();
				port = tcpPacket.getDestinationPort();

				System.out.println("TCP packet received on port " + port);
				System.out.println("TCP ERROR: ICMP port unreachable");
				break;
			case IPv4.PROTOCOL_UDP:
				UDP udpPacket = (UDP) ipPacket.getPayload();
				port = udpPacket.getDestinationPort();

				System.out.println("UDP packet received on port" + port);

				if (port != 520) {
					// TODO: port unreachable
					// TODO: ICMP.TYPE_UNREACHABLE_ERROR
					System.out.println("UDP ERROR: ICMP port unreachable");
				} else {
					// TODO: do stuff
					System.out.println("UDP packet on correct port");
				}

				break;
			default:
				System.out.println("Packet not ICMP, TCP, or UDP - Ignored");
				break;
			}
		} 
		else {
			nextHop( etherPacket );
		}
	}

	/**
	 * Create and send the appropriate ICMP Reply based on type and code arguments
	 * @param originalPacket
	 * @param inIface
	 * @param type
	 * @param code
	 */
	private void sendICMPReply(Ethernet originalPacket, Iface inIface, byte type, byte code) {
		ICMP originalIcmpPacket = null;
		IPv4 originalIpPacket = null;

		// will be using different packet types depending on what sort of ICMP
		// reply it is
		if (type == ICMP.TYPE_ECHO_REQUEST) {
			originalIcmpPacket = (ICMP) originalPacket.getPayload();
		} else {
			originalIpPacket = (IPv4) originalPacket.getPayload();
		}

		// Populate Ethernet header
		Ethernet etherPacket = new Ethernet();
		// set source MAC
		etherPacket.setSourceMACAddress( inIface.getMacAddress().toBytes() );
		// set dest MAC
		etherPacket.setDestinationMACAddress( originalPacket.getSourceMACAddress() );

		// Populate IPv4 header
		IPv4 ipPacket = new IPv4();
		// set source IP
		ipPacket.setSourceAddress( inIface.getIpAddress() );
		// set dest IP
		ipPacket.setDestinationAddress( originalIpPacket.getSourceAddress() );
		ipPacket.setTtl((byte) 255); // MAx to ensure it gets back
		ipPacket.setProtocol(IPv4.PROTOCOL_ICMP);

		// Populate ICMP header
		ICMP icmpPacket = new ICMP();
		icmpPacket.setIcmpType(type);
		icmpPacket.setIcmpCode(code);
		icmpPacket.setChecksum((short) 0); // 0 so that calculation works

		if (type == ICMP.TYPE_ECHO_REQUEST) {
			icmpPacket.setPayload(originalIcmpPacket.getPayload());
		} else { // It's unreachable error or time exceeded
					// Populate Data header
			Data dataPacket = new Data();
			ByteBuffer bb = ByteBuffer.allocate((int) originalIpPacket
					.getHeaderLength() + 8);

			bb.put(originalIpPacket.getVersion());
			bb.put(originalIpPacket.getHeaderLength());
			bb.put(originalIpPacket.getDiffServ());
			bb.putShort(originalIpPacket.getTotalLength());
			bb.putShort(originalIpPacket.getIdentification());
			bb.put(originalIpPacket.getFlags());
			bb.putShort(originalIpPacket.getFragmentOffset());
			bb.put(originalIpPacket.getTtl());
			bb.put(originalIpPacket.getProtocol());
			bb.putShort(originalIpPacket.getChecksum());
			bb.putInt(originalIpPacket.getSourceAddress());
			bb.putInt(originalIpPacket.getDestinationAddress());
			bb.put(originalIpPacket.getOptions());

			// convert payload to bytes so we can copy in the first 8
			byte[] payload = null;
			try {
				payload = Util.toByteArray(originalIpPacket.getPayload());
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			for (int i = 0; i < 8; i++) {
				bb.put(payload[i]);
			}
			dataPacket.setData(bb.array());

			// stack within ICMP payload
			icmpPacket.setPayload(dataPacket);
		}

		// stack headers
		ipPacket.setPayload(icmpPacket);
		etherPacket.setPayload(ipPacket);

		// Send ICMP reply
		if( !sendPacket( etherPacket, inIface ) ) { // send on iface we received on? 
			System.out.println( "ICMP reply could not send" );
		}
	}
	
	/**
	 * Determines and sends packet to next hop location
	 * @param etherPacket
	 */
	public boolean nextHop( Ethernet etherPacket ) {
		
		boolean success = false;
		
		RouteTableEntry destRouteEntry = findBestRoute( (IPv4)etherPacket.getPayload() );
		if( destRouteEntry == null ) {
			System.out.println("not found in route table");
			// TODO: ADD ICMP ICMP.TYPE_UNREACHABLE_ERROR
			return false;
		}
		
		ArpEntry arpMapping = lookupMacInCache( destRouteEntry, etherPacket );
		if( arpMapping != null) {
			sendResolvedPacket(etherPacket, destRouteEntry, arpMapping );
			success = true;
		}
		return success;
	}
	
	/**
	 * Finds the closest matching route table entry to the ip packet
	 * @param ipPacket
	 * @return The routing table entry that closest matches the destination, null if it does not exist
	 */
	public RouteTableEntry findBestRoute( IPv4 ipPacket ) {
		
		List<RouteTableEntry> routeTableEntries = routeTable.getEntries();
		// TODO: Find out which entry in the routing table has the longest
		// prefix match with the destination IP address.

		RouteTableEntry destRouteEntry = null;
		int longestMask = -(Integer.MAX_VALUE);

		for (RouteTableEntry entry : routeTableEntries) {
			if ((ipPacket.getDestinationAddress() & entry.getMaskAddress()) == entry
					.getDestinationAddress()) {
				// if we have more than one match, we want the most SPECIFIC
				// one (longest mask)
				if (entry.getMaskAddress() > longestMask) {
					longestMask = entry.getMaskAddress();
					destRouteEntry = entry;
				}
			}
		}

		if (destRouteEntry == null) {
			return null;
		}
		return destRouteEntry;
	}
	
	/**
	 * tries to map a destination IP address to a MAC address using the ARPCache
	 * @param destRouteEntry
	 * @param etherPacket
	 * @return returns null if there is no mapping and WaitForArp() was called
	 */
	public ArpEntry lookupMacInCache(RouteTableEntry destRouteEntry, Ethernet etherPacket ) {
		ArpEntry arpEntry = arpCache.lookup(destRouteEntry.getDestinationAddress());
		
		if( arpEntry == null ) {
			// the Mapping was not found in the ARPCache
			arpCache.waitForArp(etherPacket, interfaces.get( destRouteEntry.getInterface() ), destRouteEntry.getDestinationAddress() );
			System.out.println( "waiting for arp" );
			return null;
		}
		
		return arpEntry;
	}
	
	/**
	 * sends the packet to its destination on the correct interface
	 * @param etherPacket
	 * @param destRouteEntry
	 * @param arpEntry
	 */
	public void sendResolvedPacket( Ethernet etherPacket, RouteTableEntry destRouteEntry, ArpEntry arpEntry ) {
		// set MAC addresses on outgoing packet
		etherPacket.setSourceMACAddress( interfaces.get( destRouteEntry.getInterface() ).getMacAddress().toBytes() );
		etherPacket.setDestinationMACAddress(arpEntry.getMac().toString());
		// send packet to destination
		Iface outIface = new Iface(destRouteEntry.getInterface());
		outIface.setMacAddress(arpEntry.getMac());
		outIface.setIpAddress(destRouteEntry.getDestinationAddress());

		if( !sendPacket(etherPacket, outIface) ) {
			// TODO: sending packet failed
			System.out.println("Could not send packet, sorry");
			return;
		}
		else {
			System.out.println( "ethernet packet sent successfully :)" );
			System.out.println( etherPacket.toString() + "\n" );
		}
	}
	
}

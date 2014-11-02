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
			ICMP icmpPacket = (ICMP) packet.getPayload();
			short checksum = icmpPacket.getChecksum();
			icmpPacket.setChecksum((short) 0);
			icmpPacket.serialize();
			return (checksum == icmpPacket.getChecksum());
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

		if (etherPacket.getEtherType() == Ethernet.TYPE_ARP) {
			handleArpPacket(etherPacket, inIface);
		} else if (etherPacket.getEtherType() == Ethernet.TYPE_IPv4) {
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
		if (etherPacket.getEtherType() != Ethernet.TYPE_ARP) {
			return;
		}

		// Get ARP header
		ARP arpPacket = (ARP) etherPacket.getPayload();
		int targetIp = ByteBuffer.wrap(arpPacket.getTargetProtocolAddress())
				.getInt();

		switch (arpPacket.getOpCode()) {
		case ARP.OP_REQUEST:
			// Check if request is for one of my interfaces
			if (targetIp == inIface.getIpAddress()) {
				this.arpCache.sendArpReply(etherPacket, inIface);
			}
			break;
		case ARP.OP_REPLY:
			// Check if reply is for one of my interfaces
			if (targetIp != inIface.getIpAddress()) {
				break;
			}

			// Update ARP cache with contents of ARP reply
			int senderIp = ByteBuffer
					.wrap(arpPacket.getSenderProtocolAddress()).getInt();
			ArpRequest request = this.arpCache.insert(
					new MACAddress(arpPacket.getSenderHardwareAddress()),
					senderIp);

			// Process pending ARP request entry, if there is one
			if (request != null) {
				for (Ethernet packet : request.getWaitingPackets()) {
					if (nextHop(packet, inIface)) {
						arpCache.removeFromRequests(request);
					}
				}
			} else {
				System.out.println("request is null");
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

		// Check if this packet is on one of our interfaces
		for (Map.Entry<String, Iface> interfaceEntry : getInterfaces()
				.entrySet()) {
			if (targetAddress == interfaceEntry.getValue().getIpAddress()) {
				isOnInterface = true;
				break;
			}
		}

		if (isOnInterface) {
			// congratulations, this packet has arrived at its destination!
			byte ipProtocol = ipPacket.getProtocol();
			short port;
			switch (ipProtocol) {
			case IPv4.PROTOCOL_ICMP:

				ICMP icmpPacket = (ICMP) ipPacket.getPayload();
				if (!checkChecksum(ipPacket)) {
					System.out.println("icmp checksums do not match");
					return;
				}
				// ECHO REPLY
				System.out.println("Sending echo reply");
				sendICMPReply(etherPacket, inIface, ICMP.TYPE_ECHO_REQUEST,
						ICMP.CODE_ECHO_REQUEST);
				break;
			case IPv4.PROTOCOL_TCP:
				TCP tcpPacket = (TCP) ipPacket.getPayload();
				port = tcpPacket.getDestinationPort();

				System.out.println("TCP ERROR: TCP port unreachable");
				// PORT UNREACHABLE
				sendICMPReply(etherPacket, inIface, ICMP.TYPE_UNREACHABLE,
						ICMP.CODE_PORT_UNREACHABLE);
				break;
			case IPv4.PROTOCOL_UDP:
				UDP udpPacket = (UDP) ipPacket.getPayload();
				port = udpPacket.getDestinationPort();

				if (port != (short) 520) {
					System.out.println("UDP ERROR: UDP port unreachable");
					// PORT UNREACHABLE
					sendICMPReply(etherPacket, inIface, ICMP.TYPE_UNREACHABLE,
							ICMP.CODE_PORT_UNREACHABLE);
				} else {
					// TODO: do stuff, RIP STUFF
					System.out
							.println("UDP packet on correct port - TODO handle with RIP");
				}

				break;
			default:
				System.out.println("IP Packet not ICMP, TCP, or UDP - Ignored");
				break;
			}
		} else {
			// not intended for one of our interfaces
			if (!checkChecksum(ipPacket)) {
				System.out.println("Checksum does not match");
				return;
			}
			
			// If TTL is 0, then we need to panic!
			ipPacket.setTtl((byte) (ipPacket.getTtl() - 1));
			if ( ipPacket.getTtl() == 0) {
				System.out.println("ERROR: TTL Time Exceeded" );
				sendICMPReply(etherPacket, inIface, ICMP.TYPE_TIME_EXCEEDED,
						ICMP.CODE_TIME_EXCEEDED);
				return;
			}
			ipPacket.resetChecksum();
			ipPacket.serialize();
			
			nextHop(etherPacket, inIface);
		}
	}

	/**
	 * Create and send the appropriate ICMP Reply based on type and code
	 * arguments
	 * 
	 * @param originalPacket
	 * @param inIface
	 * @param type
	 * @param code
	 */
	public void sendICMPReply(Ethernet originalPacket, Iface inIface,
			byte type, byte code) {

		IPv4 originalIpPacket = (IPv4) originalPacket.getPayload();
		ICMP originalIcmpPacket = null;

		if (type == ICMP.TYPE_ECHO_REQUEST) {
			originalIcmpPacket = (ICMP) originalIpPacket.getPayload();
		}

		// Populate Ethernet header
		Ethernet etherPacket = new Ethernet();
		etherPacket.setSourceMACAddress(inIface.getMacAddress().toBytes());
		etherPacket.setDestinationMACAddress(originalPacket
				.getSourceMACAddress());
		etherPacket.setEtherType(Ethernet.TYPE_IPv4);

		// Populate IPv4 header
		IPv4 ipPacket = new IPv4();
		ipPacket.setSourceAddress(inIface.getIpAddress());
		ipPacket.setDestinationAddress(originalIpPacket.getSourceAddress());
		ipPacket.setTtl((byte) 255); // MAx to ensure it gets back
		ipPacket.setProtocol(IPv4.PROTOCOL_ICMP);
		ipPacket.setChecksum((short) 0);

		// Populate ICMP header
		ICMP icmpPacket = new ICMP();
		icmpPacket.setIcmpType(type);
		icmpPacket.setIcmpCode(code);
		icmpPacket.setChecksum((short) 0); // 0 so that calculation works

		if (type == ICMP.TYPE_ECHO_REQUEST) {
			icmpPacket.setPayload(originalIcmpPacket.getPayload());
			icmpPacket.serialize();
		} else { // It's unreachable error or time exceeded
			// Populate Data header
			Data dataPacket = new Data();
			ByteBuffer buf = ByteBuffer.allocate( 32 );
			
			buf.putInt( 0 );
			buf.put( originalIpPacket.serialize(), 0, 28 );
			dataPacket.setData( buf.array() );

			// stack within ICMP payload
			icmpPacket.setPayload(dataPacket);
		}

		// stack headers
		ipPacket.setPayload(icmpPacket);
		ipPacket.serialize();
		etherPacket.setPayload(ipPacket);

		// Send ICMP reply
		if (!sendPacket(etherPacket, inIface)) { 
			System.out.println("ICMP reply could not send");
		} else {
			// System.out.println( "ICMP Reply sent successfuly :)");
			// System.out.println( etherPacket.toString() + "\n" );
		}
	}

	/**
	 * Determines and sends packet to next hop location
	 * 
	 * @param etherPacket
	 */
	public boolean nextHop(Ethernet etherPacket, Iface inIface) {

		boolean success = false;

		RouteTableEntry destRouteEntry = findBestRoute((IPv4) etherPacket
				.getPayload());
		if (destRouteEntry == null) {
			System.out.println("ERROR: Net unreachable");
			sendICMPReply(etherPacket, inIface, ICMP.TYPE_UNREACHABLE,
					ICMP.CODE_NET_UNREACHABLE);
			return false;
		}

		ArpEntry arpMapping = lookupMacInCache(destRouteEntry, etherPacket);
		if (arpMapping != null) {
			sendResolvedPacket(etherPacket, destRouteEntry, arpMapping);
			success = true;
		}
		return success;
	}

	/**
	 * Finds the closest matching route table entry to the ip packet
	 * 
	 * @param ipPacket
	 * @return The routing table entry that closest matches the destination,
	 *         null if it does not exist
	 */
	public RouteTableEntry findBestRoute(IPv4 ipPacket) {

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
	 * 
	 * @param destRouteEntry
	 * @param etherPacket
	 * @return returns null if there is no mapping and WaitForArp() was called
	 */
	public ArpEntry lookupMacInCache(RouteTableEntry destRouteEntry,
			Ethernet etherPacket) {
		ArpEntry arpEntry = arpCache.lookup(destRouteEntry
				.getDestinationAddress());

		if (arpEntry == null) {
			// the Mapping was not found in the ARPCache
			arpCache.waitForArp(etherPacket,
					interfaces.get(destRouteEntry.getInterface()),
					destRouteEntry.getDestinationAddress());
			return null;
		}

		return arpEntry;
	}

	/**
	 * sends the packet to its destination on the correct interface
	 * 
	 * @param etherPacket
	 * @param destRouteEntry
	 * @param arpEntry
	 */
	public void sendResolvedPacket(Ethernet etherPacket,
			RouteTableEntry destRouteEntry, ArpEntry arpEntry) {
		// set MAC addresses on outgoing packet
		etherPacket.setSourceMACAddress(interfaces
				.get(destRouteEntry.getInterface()).getMacAddress().toBytes());
		etherPacket.setDestinationMACAddress(arpEntry.getMac().toString());
		// send packet to destination
		Iface outIface = new Iface(destRouteEntry.getInterface());
		outIface.setMacAddress(arpEntry.getMac());
		outIface.setIpAddress(destRouteEntry.getDestinationAddress());

		((IPv4) etherPacket.getPayload()).setChecksum((short) 0);

		if (!sendPacket(etherPacket, outIface)) {
			System.out.println("Could not send ethernet packet");
			return;
		} else {
			// System.out.println( "ethernet packet sent successfully :)" );
			//System.out.println( "send ether packet" );
			//System.out.println( etherPacket.toString() + "\n" );
		}
	}

}

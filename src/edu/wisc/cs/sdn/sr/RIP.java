package edu.wisc.cs.sdn.sr;

import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.RIPv2;
import net.floodlightcontroller.packet.RIPv2Entry; 
import net.floodlightcontroller.packet.UDP;
import java.util.List;
import java.util.LinkedList;
import java.util.Iterator;
import java.util.Map;
import java.util.Timer;
import java.util.Random;

/**
 * Implements RIP. 
 * @author Anubhavnidhi Abhashkumar and Aaron Gember-Jacobson
 */
public class RIP implements Runnable
{
	//can only be max of 16 according to RIP prot.
	public static final int MAX_HOPS = 16;
	public static final int RIP_MULTICAST_IP = 0xE0000009;
	private static final byte[] BROADCAST_MAC = {(byte)0xFF, (byte)0xFF, 
		(byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF};

	/** Send RIP updates every 10 seconds */
	private static final int UPDATE_INTERVAL = 10;

	/** Timeout routes that neighbors last advertised more than 30 seconds ago*/
	private static final int TIMEOUT = 30;

	/** Router whose route table is being managed */
	private Router router;

	/** Thread for periodic tasks */
	private Thread tasksThread;

	public RIP(Router router)
	{ 
		this.router = router; 
		this.tasksThread = new Thread(this);
	}

	public void init()
	{
		// If we are using static routing, then don't do anything
		if (this.router.getRouteTable().getEntries().size() > 0)
		{ return; }

		System.out.println("RIP: Build initial routing table");
		for(Iface iface : this.router.getInterfaces().values())
		{
			this.router.getRouteTable().addEntry(
					(iface.getIpAddress() & iface.getSubnetMask()),
					0, // No gateway for subnets this router is connected to
					iface.getSubnetMask(), iface.getName());
		}
		System.out.println("Route Table:\n"+this.router.getRouteTable());

		this.tasksThread.start();

		Iface iFace = null;
		byte command = RIPv2.COMMAND_REQUEST;
		sendRipPacket( null, iFace, command );

	}

	/**
	 * Handle a RIP packet received by the router.
	 * @param etherPacket the Ethernet packet that was received
	 * @param inIface the interface on which the packet was received
	 */
	public void handlePacket(Ethernet etherPacket, Iface inIface)
	{
		// Make sure it is in fact a RIP packet
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4)
		{ return; } 
		IPv4 ipPacket = (IPv4)etherPacket.getPayload();
		if (ipPacket.getProtocol() != IPv4.PROTOCOL_UDP)
		{ return; } 
		UDP udpPacket = (UDP)ipPacket.getPayload();
		if (udpPacket.getDestinationPort() != UDP.RIP_PORT)
		{ return; }
		RIPv2 ripPacket = (RIPv2)udpPacket.getPayload();

		switch( ripPacket.getCommand() ) {
		case RIPv2.COMMAND_REQUEST:
			// Someone is asking me for my info - build a response packet and send it
			sendRipPacket(etherPacket, inIface, RIPv2.COMMAND_RESPONSE );

			break;
		case RIPv2.COMMAND_RESPONSE:
			// I wanted to know someone's info, I got an answer back
			processResponse(etherPacket, inIface );
			break;
		}

	}

	public void sendRipPacket( Ethernet etherPacket, Iface inIface, byte command ) {

		Iterator<Iface> interfaces = null; 
		Iface currentInterface = null;
		boolean isLastIface = false;

		if( inIface == null ) {
			// not a response to a request, we need to broadcast to all other routers
			interfaces = this.router.getInterfaces().values().iterator();	
		}

		while( !isLastIface ) {			
			if( inIface == null ) {
				// need to iterate through and send on each interface on the router
				if( interfaces.hasNext() ) {
					currentInterface = interfaces.next();

					// take care of it if it's the last one
					if( !interfaces.hasNext() ) {
						isLastIface = true;
					}
				}
			}
			else {
				currentInterface = inIface;
				isLastIface = true;
			}	

			Ethernet newEtherPacket = new Ethernet();
			IPv4 ipPacket = new IPv4();
			UDP udpPacket = new UDP();
			RIPv2 ripPacket = new RIPv2();

			// Construct ethernet header
			newEtherPacket.setEtherType( Ethernet.TYPE_IPv4 );
			newEtherPacket.setSourceMACAddress( currentInterface.getMacAddress().toBytes() );
			if( inIface != null ) {
				newEtherPacket.setDestinationMACAddress( etherPacket.getSourceMACAddress() );				
			}
			else {
				newEtherPacket.setDestinationMACAddress( BROADCAST_MAC );
			}
			newEtherPacket.resetChecksum();

			// construct IP header
			ipPacket.setSourceAddress( currentInterface.getIpAddress() );
			if( inIface != null ) {
				ipPacket.setDestinationAddress( ((IPv4)etherPacket.getPayload()).getSourceAddress() );
			}
			else {
				ipPacket.setDestinationAddress( RIP_MULTICAST_IP );
			}
			ipPacket.setTtl( (byte)64 );
			ipPacket.setProtocol( IPv4.PROTOCOL_UDP );
			ipPacket.resetChecksum();

			// construct UDP header
			udpPacket.setSourcePort( (short)520 );
			udpPacket.setDestinationPort( (short)520 );
			udpPacket.resetChecksum();

			// construct RIP header
			ripPacket.setCommand( command );
			for( RouteTableEntry entry : this.router.getRouteTable().getEntries() ) {
				/* SPLIT HORIZON: If the entry's destination is where we are sending the packet,
				 * we don't want to send it because that's dumb
				 * */

				if( entry.getDestinationAddress() != ( (etherPacket == null) ? 0 : ( (IPv4)etherPacket.getPayload() ).getDestinationAddress() ) ) {
					// when reading the metric, need to +1 to account for current hop
					RIPv2Entry ripEntry = new RIPv2Entry( entry.getDestinationAddress(), entry.getMaskAddress(), entry.getCost() + 1 );
					ripEntry.setNextHopAddress( currentInterface.getIpAddress() );
					ripPacket.addEntry( ripEntry );
				}
			}
			ripPacket.resetChecksum();

			// nest within each other
			ripPacket.serialize();
			udpPacket.setPayload( ripPacket );
			udpPacket.serialize();
			ipPacket.setPayload( udpPacket );
			ipPacket.serialize();
			newEtherPacket.setPayload( ipPacket );
			newEtherPacket.serialize();

			this.router.sendPacket( newEtherPacket, currentInterface );
		}
	}

	public void processResponse( Ethernet packet, Iface inIface ) {
		// hello we got a response, let's parse through all the important info
		Ethernet etherPacket = packet;
		IPv4 ipPacket = (IPv4)packet.getPayload();
		UDP udpPacket = (UDP)ipPacket.getPayload();
		RIPv2 ripPacket = (RIPv2)udpPacket.getPayload();
		RouteTable routeTable = this.router.getRouteTable();
		boolean hasUpdated = false;

		for( RIPv2Entry ripEntry : ripPacket.getEntries() ) {			
			if( ripEntry.getMetric() > MAX_HOPS ) {
				// don';t want to deal with this packet
				continue;
			}
			// check if our route table entries show up in this packet
			RouteTableEntry foundEntry = routeTable.findEntry(ripEntry.getAddress(), ripEntry.getSubnetMask() );

			if( foundEntry == null ) {
				// entry is in the packet and not in the routing table - ADD IT
				routeTable.addEntry( ripEntry.getAddress(), inIface.getIpAddress(), ripEntry.getSubnetMask(), inIface.getName(), ripEntry.getMetric() );
				hasUpdated = true;
			}
			else {
				// the entry is in the table

				if ( ripEntry.getMetric() < foundEntry.getCost())  {
					// SHORTER PATH FOUND
					routeTable.updateEntry( ripEntry.getAddress(), ripEntry.getSubnetMask(), inIface.getIpAddress(), inIface.getName(), ripEntry.getMetric() );
					hasUpdated = true;
				}

				if ( ripEntry.getMetric() == foundEntry.getCost()) {
					// update timestamp to keep it alive - this is the same entry
					foundEntry.setTimeStamp();					
				}
			}
		}
		if( hasUpdated ) {
			// tell everyone that we updated
			sendRipPacket( null, null, RIPv2.COMMAND_RESPONSE );
		}
	}

	/**
	 * Perform periodic RIP tasks.
	 */
	@Override
	public void run() 
	{
		//Send out timed updates of your table every 10 seconds
		//iterate through interfaces and send out packet on every one (RIP.UPDATE_INTERVAL)

		while(true){
			try{
				tasksThread.sleep(RIP.UPDATE_INTERVAL*1000);
			}
			catch(Exception e){
				System.out.println(e.getMessage());
			}

			
			//iterate through table entries
			for(RouteTableEntry routeTableEntry: this.router.getRouteTable().getEntries()){ 
			//current time - timestamps >= time out
				if (routeTableEntry.getGatewayAddress() != 0 && ( System.currentTimeMillis()/1000L - routeTableEntry.getTimestamp() >= TIMEOUT) ){
					//remove entry
					this.router.getRouteTable().removeEntry(routeTableEntry.getDestinationAddress(), routeTableEntry.getMaskAddress());
				}
			}
			
			// tell your friends!
			sendRipPacket(null, null, RIPv2.COMMAND_RESPONSE );
		}
	}
}


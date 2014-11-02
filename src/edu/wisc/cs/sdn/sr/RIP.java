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
    private static final int RIP_MULTICAST_IP = 0xE0000009;
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

		/**
		 * Katie's notes on Distance Vector Calculations:
		 * 1. each "node" only knows it's own routing table and inits with it's iFaces
		 * 2. other nodes are known to be reachable only after being informed by other nodes(RIP pkt?)
		 * 
		 * when update:
		 * Periodic - auto sends a routing update to its neighbors, even if nothing has changed
		 * 		lets other nodes it is still running
		 * Triggered - when a node notices a link failure or receives an update
		 * 		whenever a node's routing table changes, it send an update to neighbors
		 * 
		 * When a node fails:
		 * How check? Periodically checks if link up and/or did not receive update in X time/cylcles
		 * 
		 * Count to infinity problem:
		 * Circle updates. 
		 * Solution?
		 * 1. Max hops = infinity?
		 * 2. Split horizon = do not send updates to neighbors from which it *received* the update
		 * 		ex. (B has entry (E, 2, A), meaning it learned the route to E through A likely through A, 
		 * 			so does not advertise the path to E to A)
		 * 3. Split horizon with poison reverse = B sends update to A, but with a neg num for E,
		 * 		ensuring that A does not use B to get to E should its own link go down.
		 * 
		 * There is a background process decrementing TTL, discarding routes that have a time to live of 0
		 * TTL is reset to MAX any time the route is reconfirmed by an update message
		 * 
		 * Add new route if not at MAXROUTES, else ignore.
		 * 
		 * mergeRoute(Route new)//updates entry if better path
		 * updateRoutingTable(Route neewRoute, int numNewRoutes)//main routing that calls merge
		 * 		incorporates all routes contained in a routing update
		 ***/
		
		/**
		 * Katie's notes on RIP:
		 * 
		 * Routers running RIP send advertisements every 30 seconds
		 * also sends update message whenever an update from another routers changes it routing table.
		 * 
		 * It supports multiple address families, not just IP. 
		 * 
		 * v2 also introduced subnet masks
		 * 
		 * possible to use range of diff metrics or costs for the links.
		 * 
		 * RIP takes simplest approch, with all link costs being equal to 1; 
		 * thus, always tries to find minimum hop route
		 * 
		 * Valid distances are 1 through 15, 16 representing infinity. 
		 * 
		 * Limits RIP to running on fairly small networks - those with paths no longer than 15 hops
		 */
        /*********************************************************************/
        /* TODO: Add other initialization code as necessary
+		   if not a static static routing table...
+		   	populates the route table with entries
+		   	for the subnets that are directly reachable
+		   	via the router's interfaces, starts a
+		   	thread for period RIP tasks, and performs
+		   	other initialization for RIP as necessary
+		*/

        /*********************************************************************/
		
		//TODO	
		//iterate through every interface for this router and send RIP request
		for (Map.Entry<String, Iface> interfaceEntry : this.router.getInterfaces().entrySet()) {
			
			
			//add to list of RouteTableEntries
			//send RIP packet
			
			
		}
		
		
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

        /*********************************************************************/
        /* TODO: Handle RIP packet
+			If NOT a static routing table
+			Processes a RIP packet that is received by the router
+
+		*/

        /*********************************************************************/
	}

    //TODO: FOR CONTROL PLANE
    /**
      * Perform periodic RIP tasks.
      */
	@Override
	public void run() 
    {
        /*********************************************************************/
        /* TODO: Send period updates and time out route table entries
+			if no static routing table provided
+			send updates to neighbors
+			time out route table entries that neighbors last advertised > 30 secds ago
+		*/

        /*********************************************************************/
		
		//Send out timed updates of your table every 10 seconds
		//iterate through interfaces and send out packet on every one (RIP.UPDATE_INTERVAL)
	}
}

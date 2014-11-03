package edu.wisc.cs.sdn.sr;

/**
 * An entry in a route table.
 * 
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class RouteTableEntry {
	/** Destination IP address */
	private int destinationAddress;

	/** Gateway IP address */
	private int gatewayAddress;

	/** Subnet mask */
	private int maskAddress;

	/**
	 * Name of the router interface out which packets should be sent to reach
	 * the destination or gateway
	 */
	private String interfaceName;

	// never to exceed 16
	private int cost;
	private long timeStamp;

	// private int timer = 0;

	public RouteTableEntry(int destinationAddress, int gatewayAddress,
			int maskAddress, String ifaceName, int cost) {
		this.destinationAddress = destinationAddress;
		this.gatewayAddress = gatewayAddress;
		this.maskAddress = maskAddress;
		this.interfaceName = ifaceName;
		// add cost of hop
		this.cost = cost;
		// add timeStamp of when first added
		this.timeStamp = System.currentTimeMillis() / 1000L;
	}

	/**
	 * Create a new route table entry.
	 * 
	 * @param destinationAddress
	 *            destination IP address
	 * @param gatewayAddress
	 *            gateway IP address
	 * @param maskAddress
	 *            subnet mask
	 * @param ifaceName
	 *            name of the router interface out which packets should be sent
	 *            to reach the destination or gateway
	 */
	public RouteTableEntry(int destinationAddress, int gatewayAddress,
			int maskAddress, String ifaceName) {
		this.destinationAddress = destinationAddress;
		this.gatewayAddress = gatewayAddress;
		this.maskAddress = maskAddress;
		this.interfaceName = ifaceName;
		this.cost = 1;
	}

	/**
	 * @return destination IP address
	 */
	public int getDestinationAddress() {
		return this.destinationAddress;
	}

	/**
	 * @return gateway IP address
	 */
	public int getGatewayAddress() {
		return this.gatewayAddress;
	}

	public void setGatewayAddress(int gatewayAddress) {
		this.gatewayAddress = gatewayAddress;
	}

	public int getCost() {
		return this.cost;
	}

	public void setCost(int cost) {
		this.cost = cost;
	}

	public long getTimestamp() {
		return this.timeStamp;
	}

	public void setTimeStamp() {
		this.timeStamp = System.currentTimeMillis() / 1000L;
	}

	/**
	 * @return subnet mask
	 */
	public int getMaskAddress() {
		return this.maskAddress;
	}

	/**
	 * @return name of the router interface out which packets should be sent to
	 *         reach the destination or gateway
	 */
	public String getInterface() {
		return this.interfaceName;
	}

	public void setInterface(String interfaceName) {
		this.interfaceName = interfaceName;
	}

	public String toString() {
		String result = "";
		result += Util.intToDottedDecimal(destinationAddress) + "\t";
		String gwString = Util.intToDottedDecimal(gatewayAddress);
		result += gwString + "\t";
		if (gwString.length() < 8) {
			result += "\t";
		}
		result += Util.intToDottedDecimal(maskAddress) + "\t";
		result += interfaceName + "\t";
		result += cost;

		return result;
	}
}

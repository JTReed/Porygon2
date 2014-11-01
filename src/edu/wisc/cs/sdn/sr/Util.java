package edu.wisc.cs.sdn.sr;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;

import net.floodlightcontroller.packet.IPacket;

/**
 * @author Aaron Gember-Jacobson
 */
public class Util 
{
	/**
	 * Convert an integer representing an IP address into a string with the IP
	 * address in dotted decimal format.
	 * @param ip integer representing an IP address
	 * @return string with the IP address in dotted decimal format
	 */
	public static String intToDottedDecimal(int ip)
	{
		int[] addr = new int[4];
		for (int i = 3; i >= 0; i--)
		{ 
			addr[i] = (ip & 0xFF);
			ip = ip >> 8;
		}
		return String.format("%d.%d.%d.%d", addr[0], addr[1], addr[2], addr[3]);
	}
	
	/**
	 * Convert a string with the IP address in dotted decimal format into an 
	 * integer representing the IP address.
	 * @param ip string with an IP address in dotted decimal format
	 * @return integer representing the IP address
	 */
	public static int dottedDecimalToInt(String ip)
	{
		try 
		{ return ByteBuffer.wrap(InetAddress.getByName(ip).getAddress()).getInt(); }
		catch (UnknownHostException e) 
		{ return 0; }
	}
	
	// converts any object into a byte[]
	// from http://www.java2s.com/Code/Java/File-Input-Output/Convertobjecttobytearrayandconvertbytearraytoobject.htm
	public static byte[] toByteArray(Object obj) throws IOException {
		byte[] bytes = null;
		ByteArrayOutputStream bos = null;
		ObjectOutputStream oos = null;
		try {
			bos = new ByteArrayOutputStream();
			oos = new ObjectOutputStream(bos);
			oos.writeObject(obj);
			oos.flush();
			bytes = bos.toByteArray();
		} finally {
			if (oos != null) {
				oos.close();
			}
			if (bos != null) {
				bos.close();
			}
		}
		return bytes;
	}
}

/**
 * Esta clase describe las funcionalidad del objeto Sniffer.
 * @package Sniffer
 * @subpackage Clases
 * @author RR Soluciones IT SAS
 * @version  1.0.0
 * @copyright 2018
 */
package Sniffer.class;
import java.net.*;
import java.io.*;
import jpcap.JpcapCaptor.*;
import jpcap.JpcapSender;
import jpcap.NetworkInterface.*;
import jpcap.NetworkInterfaceAddress;
import jpcap.packet.*;
	
class Sniffer{
	/**
	 *@description Variables de la clase
	 */
	JpcapCaptor captor;
    NetworkInterface[] list;
    String str,info;
    int x, choice;
    /**
     * @function main
     * @param String args
     * @description 
     */
    public static void main(String args[]){
    	new Sniffer();
    }
    /**
     * @function Sniffer
     * @param 
     * @description Constructor de la clase Sniffer
     */
    public Sniffer(){
    	list = JpcapCaptor.getDeviceList();
    	System.out.println("Available interfaces: ");
    	for(x=0; x<list.length; x++){
    		System.out.println(x+" -> "+list[x].description);
    	}
    	choice = Integer.parseInt(obtenerEntrada("Choose interface (0,1..): "));
    	System.out.println("Listening on interface -> "+list[choice].description);
    	try{
    	    captor=JpcapCaptor.openDevice(list[choice], 65535, false, 20);
    	    captor.setFilter("ip and tcp", true);
    	}
    	catch(IOException ioe){ 
    		ioe.printStackTrace(); 
    	}
    	while(true){
    		Packet info = captor.getPacket();
    		if(info != null)
    			System.out.print(obtenerPaquete(info));
    	}
    }
    /**
     * @function obtenerEntrada
     * @param String q
     * @description 
     */
    public static String obtenerEntrada(String q){
    	String input = "";
    	System.out.print(q);
    	BufferedReader bufferedreader = new BufferedReader(new InputStreamReader(System.in));
    	try{
    		input = bufferedreader.readLine();
    	}
    	catch(IOException ioexception){
    	}
    	return input;
    }
    /**
     * @function obtenerEntrada
     * @param String q
     * @description 
     */
    String obtenerPaquete(Packet pack){
    	int i=0,j=0;
    	byte[] bytes=new byte[pack.header.length + pack.data.length];
    	System.arraycopy(pack.header, 0, bytes, 0, pack.header.length);
    	System.arraycopy(pack.data, 0, bytes, pack.header.length, pack.data.length);
    	StringBuffer buffer = new StringBuffer();
    	for(i=0; i<bytes.length;){
    		for(j=0;j<8 && i<bytes.length;j++,i++){
    			String d = Integer.toHexString((int)(bytes [i] &0xff));
    			buffer.append((d.length() == 1 ? "0" + d:d ) + " ");
    			if(bytes[i]<32 || bytes[i]>126) 
    				bytes[i] = 46;
    		}
    	}
    	return new String(bytes,i - j, j);
    }
}

package Couches;

import static org.junit.Assert.assertEquals;

import java.util.ArrayList;
import java.util.List;

import pobj.tools.Tools;

public class Dhcp implements ICouches {
	private Udp udp;
	private String opcode;
	private String  hardwareType;
	private String hardwareAdressLength;
	private String hops;
	private String xid;
	private String sec;
	private String flags;
	private String ciaddr; // client ip adress
	private String yiaddr; // your ip adress
	private String siaddr; //server Ip adress
	private String giaddr; //gateway Ip adress
	
	private String chaddr; // client hardware addresses 16 octet
	private String chaddrPadding;
	private String serverName ; //serverName 64 octet
	private String bootFileName; // 128 octet;
	
	private String magicCookie ;
	private List<OptionDHCP> options; 
	
	private List<String> enteteDHCP ; 
	
	private List<String> data;
	
	public Dhcp(Udp udp) throws Exception {
		this.udp = udp;
		getChamp(udp.getData());
	}
	
	public Udp getUdp() {
		return udp;
	}

	public void setUdp(Udp udp) {
		this.udp = udp;
	}

	public void getChamp(List<String> trame) throws Exception {
		/*if(trame.size()< Tools.convertHextoDec(udp.getLength())) {
			throw new Exception("udp length problem"  + trame.size() +" < " +Tools.convertHextoDec(udp.getLength()));
		}*/
		enteteDHCP = trame.subList(0, Tools.convertHextoDec(udp.getLength())-8);
		/*if(trame.size() > Tools.convertHextoDec(udp.getLength())-8 ) {
			data =trame.subList(Tools.convertHextoDec(udp.getLength())-8, trame.size() );
		}else {
			data = null;
		}*/
		
		options = new ArrayList<>();
		
		int i = 0;
		opcode = enteteDHCP.get(i++);
		hardwareType = enteteDHCP.get(i++);
		hardwareAdressLength = enteteDHCP.get(i++);
		hops = enteteDHCP.get(i++);
		xid = enteteDHCP.get(i++) +  enteteDHCP.get(i++) + enteteDHCP.get(i++)+ enteteDHCP.get(i++);
		
		sec = enteteDHCP.get(i++) +enteteDHCP.get(i++);
		flags = enteteDHCP.get(i++) + enteteDHCP.get(i++);
		ciaddr =Tools.convertHextoDec(enteteDHCP.get(i++)) + "." + Tools.convertHextoDec(enteteDHCP.get(i++)) + "." + Tools.convertHextoDec(enteteDHCP.get(i++)) + "."+ Tools.convertHextoDec(enteteDHCP.get(i++));
		yiaddr =Tools.convertHextoDec(enteteDHCP.get(i++)) + "." + Tools.convertHextoDec(enteteDHCP.get(i++)) + "." + Tools.convertHextoDec(enteteDHCP.get(i++)) + "."+ Tools.convertHextoDec(enteteDHCP.get(i++));
		siaddr = Tools.convertHextoDec(enteteDHCP.get(i++)) + "." + Tools.convertHextoDec(enteteDHCP.get(i++)) + "." + Tools.convertHextoDec(enteteDHCP.get(i++)) + "."+ Tools.convertHextoDec(enteteDHCP.get(i++));
		giaddr =Tools.convertHextoDec(enteteDHCP.get(i++)) + "." + Tools.convertHextoDec(enteteDHCP.get(i++)) + "." + Tools.convertHextoDec(enteteDHCP.get(i++)) + "."+ Tools.convertHextoDec(enteteDHCP.get(i++));
		chaddr =  enteteDHCP.get(i++) +":" +enteteDHCP.get(i++) +":" + enteteDHCP.get(i++) +":" + enteteDHCP.get(i++)+":" + enteteDHCP.get(i++)+ ":" +enteteDHCP.get(i++) ;
		chaddrPadding = "";
		int n = i +10;
		for(; i<n ; i++) {
			chaddrPadding += enteteDHCP.get(i);
		}
		assertEquals(20, chaddrPadding.length());
		serverName = enteteDHCP.get(i++);
		n = i +63 ; 
		for(; i< n ; i++) {
			serverName += " " + enteteDHCP.get(i);
		}
		
		
		bootFileName = enteteDHCP.get(i++);
		
		n = i+127;
		for(; i<n ; i++) {
			bootFileName += " " +enteteDHCP.get(i);
		}
		
		magicCookie = enteteDHCP.get(i++) +  enteteDHCP.get(i++) + enteteDHCP.get(i++)+ enteteDHCP.get(i++);
		
		while (i< enteteDHCP.size()) {
			String tag = enteteDHCP.get(i++);
			if(Tools.convertHextoDec(tag) == 0 || Tools.convertHextoDec(tag) == 255) {
				if(Tools.convertHextoDec(tag) == 255) {
					OptionDHCP op = new OptionDHCP(tag);
					
					options.add(op);
				}
				
				
			}else {
				String length = enteteDHCP.get(i++);
				int lengthOption = i+ Tools.convertHextoDec(length);
				List<String> tmp = enteteDHCP.subList(i, lengthOption);
				OptionDHCP op = new OptionDHCP(tag, length, tmp);
				op.toString();
				options.add(op);
				i = i+ Tools.convertHextoDec(length);
				
			}
			
		}
	}
	@Override
	public String analyse() {
		// TODO Auto-generated method stub
		StringBuilder sb = new StringBuilder();
		sb.append("Dnymamic Host Configuration : \n\t");
		sb.append("Message type : ");
		if(Tools.convertHextoDec(opcode)==Tools.convertHextoDec("01")) {
			sb.append("Boot Request (1)\n\t");
		}
		if(Tools.convertHextoDec(opcode)==Tools.convertHextoDec("02")) {
			sb.append("Boot Reply (2)\n\t");
		}
		sb.append("Hardware type : ");
		switch(Tools.convertHextoDec(hardwareType)) {
		case 1:
			sb.append("Ethernet (0x");
			break;
			
		case 6:
			sb.append("IEEE 802 Networks (0x");
			break;
			
		case 7 : 
			sb.append("ARCNET (0x");
			break;
			
		case 11 :
			sb.append("LocalTalk (0x");
			break;
			
		case 12:
			sb.append("LocalNet (0x");
			break;
			
			
		case 14 :
			sb.append("SMDS (0x");
			break;
			
		case 15:
			sb.append("Frame Relay (0x");
			break;
			
		case 16 :
			sb.append("Asynchronous Transfer Mode (0x");
			break;
			
		case 17 :sb.append("HDLC (0x");
			break;
			
		case 18:sb.append("Fibre Channel (0x");
			break;
			
		case 19 :
			sb.append("Asynchronous Transfer Mode (0x");
			break;
			
	    case 20 :
	    	sb.append("Serial Line (0x");
			break;
			
		default:
			sb.append("unable to analyse option type");
	}
		sb.append(hardwareType+")\n\t");
		sb.append("Hardware address length : "+Tools.convertHextoDec(hardwareAdressLength)+"\n\t");
		sb.append("Hops : "+Tools.convertHextoDec(hops)+"\n\t");
		sb.append("Transaction ID : 0x"+xid+"\n\t");
		sb.append("Seconds elapsed : "+Tools.convertHextoDec(sec)+"\n\t");
		sb.append("Bootp flags : 0x"+flags);
		String binFlags = Tools.convertHextoBin(flags);
		String b = binFlags.substring(0, 1);
		if(Tools.convertBintoDec(b) == 0 ) {
			sb.append("(Unicast)\n\t");
		}
		if(Tools.convertBintoDec(b) == 1) {
			sb.append("(Broadcast)\n\t");
		}
		sb.append("Client IP address : "+ciaddr+"\n\t");
		sb.append("Your (Client) IP address : "+yiaddr+"\n\t");
		sb.append("Next Server Ip address: "+siaddr+"\n\t");
		sb.append("Relay agent IP address : "+giaddr+"\n\t");
		sb.append("Client MAC address : " + chaddr + "\n\t");
		sb.append("Client hardware address padding : " + chaddrPadding + "\n\t");
		if(Tools.convertHextoDec(serverName.substring(0, 2))==Tools.convertHextoDec("00")) {
			sb.append("Server host name not given\n\t");
		}else {
			sb.append("Server host name : " + Tools.hexToASCII(serverName) + "\n\t");
		}
		if(Tools.convertHextoDec(bootFileName.substring(0, 2))==Tools.convertHextoDec("00")) {
			sb.append("Boot file name not given\n\t");
		}else {
			sb.append("Boot file name : " + Tools.hexToASCII(bootFileName) + "\n\t");
		}
		sb.append("Magic cookie : DHCP\n\t");
		for(OptionDHCP op : options) {
			sb.append(op.analyse());
		}
		
		
		
		return sb.toString();
	}
	
	
}

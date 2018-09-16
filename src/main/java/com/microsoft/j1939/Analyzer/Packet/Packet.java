package com.microsoft.j1939.Analyzer.Packet;

/**
 * Controller Area Network (CAN) analyzer for Hadoop
 * 
 * Process a J1939 Packet utilising the ID to determine the PGN and ID determine the packet 
 * type
 * 
 * @author Neil Brittliff
 * 
 */
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.util.List;
import java.util.Map;

import org.apache.commons.codec.binary.Hex;
import org.joda.time.DateTime;

import com.microsoft.j1939.Analyzer.Schema.Message;

public class Packet {
	public enum PacketType {
		SINGLE, BAM, RTS, CTS, ACK, ABORT, TPDATA, REQUEST, ACKNOWLEDGE, ADDRESCLAIM, OTHER
	}

	PacketType packetType;
	byte[] data;
	long counter = 0;
	long id = 0;

	public long getId() {
		return id;
	}

	public void setId(long id) {
		this.id = id;
	}

	DateTime timeStamp;
	public DateTime getTimeStamp() {
		return timeStamp;
	}

	double clock = 0;
	public double getClock() {
		return clock;
	}

	long source = 0;
	int packets = 0;
	int ctsPackets = 0;
	long priority = 0;
	long pgn = 0;
	long destination = 0;
	long sequence = 0;
	long pf;
	boolean extDataPage = false;
	boolean dataPage = false;

	final Map<String, Message> messageMap;
	List<Transmission> events = null;

	public List<Transmission> getTransmissions() {
		return events;
	}

	Message message; 
	
	public Message getMessage() {
		return message;
	}

	/**
	 * The J1939 Packet Constructor
	 * 
	 * @param messageMap
	 *            this is used to translate messages and signals
	 * @param counter
	 *            the Current Record
	 * @param dateTime
	 *            the Date Time of the Event
	 * @param clock
	 *            the Clock
	 * @param id
	 *            the Id of the Packet
	 * @param data
	 *            the packet's data
	 * @throws IOException 
	 */
	public Packet(Map<String, Message> messageMap, long counter, DateTime dateTime, double clock, long id,
			byte[] data) throws IOException {

		this.messageMap = messageMap;

		this.counter = counter;
		this.timeStamp = dateTime;
		this.data = data;
		this.clock = clock;
		this.id = id;

		source = id & 0x000000FF;

		pf = (id & 0x00FF0000) >> 16;

		if (pf >= 0xF0) {
			pgn = (id & 0x01FFFF00) >> 8;
			packetType = PacketType.SINGLE;
			packets = 1;
		} else {
			pgn = (id & 0x01FF0000) >> 8;
			destination = (id & 0x0000FF00) >> 8;

		}

		priority = (id & 0x1C000000) >> 26;
		extDataPage = (id & 0x02000000) != 0x00000000;
		dataPage = (id & 0x01000000) != 0x00000000;

		processPGN(pgn, data);
		
		message = getMessage(id);
		
		if (message != null) {
			PacketAnalyzer analyzer = new PacketAnalyzer(message, id, pgn, data);
			
			events = analyzer.analyze();
		}

	}

	/**
	 * Process the PGN
	 * 
	 * @param pgn
	 *            the PGN to process
	 * @param data
	 *            the data
	 */
	void processPGN(long pgn, byte[] data) {

		switch ((int) pgn) {
		case 0xEC00 /* 60416 - BAM Message */:
			packetType = (data[0] == 32) ? PacketType.BAM
					: (data[0] == 16) ? PacketType.RTS
							: (data[0] == 17) ? PacketType.CTS
									: (data[0] == 19) ? PacketType.ACK : PacketType.ABORT;
			processPacket(packetType, pgn, data);
			break;

		case 0xEB00 /* 60160 */ :
			packetType = PacketType.TPDATA;
			this.pgn = pgn;
			this.data = data;
			this.packets = 1;
			this.sequence = Byte.toUnsignedInt(data[0]);
			break;

		case 0xEA00 /* 59904 */ :
			packetType = PacketType.REQUEST;
			pgn = Byte.toUnsignedInt(data[0]) | (Byte.toUnsignedInt(data[1]) << 8)
					| (Byte.toUnsignedInt(data[2]) << 16);
			this.data = data;
			this.packets = 1;
			break;

		case 0xE800 /* 59392 */ :
			packetType = PacketType.ACKNOWLEDGE;
			this.pgn = pgn;
			this.data = data;
			this.packets = 1;
			break;

		case 0xEE00: /* 60928 */
			packetType = PacketType.ADDRESCLAIM;
			this.pgn = pgn;
			this.data = data;
			this.packets = 1;
			break;

		default:
			packetType = PacketType.SINGLE;
			this.pgn = pgn;
			this.data = data;
			this.packets = 1;
			break;

		}

	}

	private void processPacket(PacketType packetType, long pgn, byte[] data) {
		switch (packetType) {
		case BAM:
			this.data = new byte[Byte.toUnsignedInt(data[1]) | (Byte.toUnsignedInt(data[2]) << 8)];
			packets = Byte.toUnsignedInt(data[3]);
			pgn = Byte.toUnsignedInt(data[5]) | (Byte.toUnsignedInt(data[6]) << 8)
					| (Byte.toUnsignedInt(data[7]) << 16);
			this.id = pgn << 8 + source;
			break;
		case RTS: {
			int byteSize = Byte.toUnsignedInt(data[1]) | (Byte.toUnsignedInt(data[2]) << 8);
			packets = Byte.toUnsignedInt(data[3]);
			ctsPackets = Byte.toUnsignedInt(data[4]);
			pgn = Byte.toUnsignedInt(data[5]) | (Byte.toUnsignedInt(data[6]) << 8)
					| (Byte.toUnsignedInt(data[7]) << 16);
			data = new byte[byteSize];
			this.id = pgn << 8 + source;
		}
			break;
		case CTS:
			ctsPackets = Byte.toUnsignedInt(data[1]);
			sequence = Byte.toUnsignedInt(data[2]);
			pgn = Byte.toUnsignedInt(data[5]) | (Byte.toUnsignedInt(data[6]) << 8)
					| (Byte.toUnsignedInt(data[7]) << 16);
			break;
		case ACK:
			int byteSize = Byte.toUnsignedInt(data[1]) | (Byte.toUnsignedInt(data[2]) << 8);
			packets = Byte.toUnsignedInt(data[3]);
			pgn = Byte.toUnsignedInt(data[5]) | (Byte.toUnsignedInt(data[6]) << 8)
					| (Byte.toUnsignedInt(data[7]) << 16);
			break;
		case ABORT:
			pgn = Byte.toUnsignedInt(data[5]) | (Byte.toUnsignedInt(data[6]) << 8)
					| (Byte.toUnsignedInt(data[7]) << 16);
			break;
		default:

			break;
		}
	}

	/**
	 * Debug output 
	 * @param outputStream the Output Stream
	 * @throws IOException 
	 */
	public void debug(OutputStream outputStream) throws IOException {
		Message message = getMessage(id);
		
		writeLine(outputStream, "Record: [" + counter + "]");
		writeLine(outputStream, "	Time: '" + timeStamp.toString() + "'");
		writeLine(outputStream, "	Clock: '" + Double.toString(clock / 1000) + "'");
		writeLine(outputStream, "	Data: '" + "0x" + Hex.encodeHexString(data).toUpperCase() + "'");
		writeLine(outputStream, "	ID: '" + "0x" + BigInteger.valueOf(id).toString(16).toUpperCase()
				+ "' - '" + (message == null ? "" : message.getName()) + "'");
		writeLine(outputStream, "	PF: '" + pf + "'");
		writeLine(outputStream, "	PGN: '" + pgn + "' - '0x" + BigInteger.valueOf(pgn).toString(16).toUpperCase() + "'");
		writeLine(outputStream, "	Source: '" + source + "'");
		writeLine(outputStream, "	Priority: '" + priority + "'");
		writeLine(outputStream, "	ExtData Page: '" + extDataPage + "'");
		writeLine(outputStream, "	Data Page: '" + dataPage + "'");
		writeLine(outputStream, "	Sequence: '" + sequence + "'");
		writeLine(outputStream, "	Packets: '" + packets + "'");
		
		if (events != null) {
			writeLine(outputStream, "	Signals: ");
			
			for (Transmission signal : events) {
				
				writeLine(outputStream, "	  Signal: '" + signal.getSignal().getName() + "' - " + signal.getValueAsLong() + " - " + signal.getValueAsHex());
		
			}
		}	
		
		writeLine(outputStream, "");

	}
	
	/**
	 * Write to an outputStream
	 * @param outputStream the output stream
	 * @param line the line to write out
	 * 
	 * @throws IOException
	 */
	public void writeLine(OutputStream outputStream, String line) throws IOException {
		
		outputStream.write((line + "\n").getBytes(Charset.forName("UTF-8")));
		
	}
	
	/**
	 * Look up a table to get the message
	 * 
	 * @param id the 'ID' of the message
	 * @return the message or null if not found
	 */
	public Message getMessage(long id) {
		String idValue = "0x" + BigInteger.valueOf(id).toString(16).toUpperCase();
		
		if (messageMap.containsKey(idValue)) {
			return messageMap.get(idValue);
		} else {	
			return null;
		}
		
	}

}
package com.microsoft.j1939.Analyzer.Packet;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.BitSet;
import java.util.LinkedList;
import java.util.List;

/**
 * Controller Area Network (CAN) analyzer for Hadoop
 * 
 * Process a J1939 Packet and associated Signals
 * 
 * @author Neil Brittliff
 * 
 */
import com.microsoft.j1939.Analyzer.Schema.Message;
import com.microsoft.j1939.Analyzer.Schema.Signal;

public class PacketAnalyzer {
	final Message message;
	final long id;
	final long pgn;
	final byte[] data;
	
	/**
	 * J1939 Signal Processor for a specific packet
	 * 
	 * @param message the Message 
	 * @param id the Message ID
	 * @param pgn 
	 * @param data the Message's Data
	 */
	public PacketAnalyzer(Message message, long id, long pgn, byte[] data) {

		this.message = message;
		this.id = id;
		this.pgn = pgn;
		this.data = data;

	}

	public List<Transmission> analyze() throws IOException {
		List<Transmission> signals = new LinkedList<Transmission>();
		
		for (Signal signal : message.getSignal()) {
			ByteBuffer buffer = ByteBuffer.allocate(data.length);
			
			buffer.order(signal.getEndianess().equals("little") ? 
						ByteOrder.LITTLE_ENDIAN : ByteOrder.BIG_ENDIAN);
			buffer.put(data);
			
			BitSet bitSet = BitSet.valueOf(buffer.array());		
			BitSet value = bitSet.get(signal.getOffset(), signal.getOffset() + signal.getLength());	
	
			signals.add(new Transmission(signal, value));
			
		}
		
		return signals;
		
	}

	
}

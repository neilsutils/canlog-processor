package com.microsoft.j1939.Analyzer.Packet;

/**
 * Controller Area Network (CAN) analyzer for Hadoop
 * 
 * Process a J1939 Signal Tranmission utilising the Signal ID from the  
 * 
 * @author Neil Brittliff
 * 
 */
import java.util.BitSet;
import org.apache.commons.codec.binary.Hex;
import com.microsoft.j1939.Analyzer.Schema.Signal;


public class Transmission {
	public Signal getSignal() {
		return signal;
	}

	public BitSet getValue() {
		return value;
	}

	final Signal signal;
	final BitSet value;
	
	/**
	 * CanSignal constructor 
	 * @param signal the Signal definition from the Schema
	 * @param value the Value of the Signal
	 */
	Transmission(Signal signal, BitSet value) {
		
		this.signal = signal;
		this.value = value;
		
	}
	
	/**
	 * The Signal Value as a long
	 * @return the Signal's value - long
	 */
	public long getValueAsLong() {
		
		return convert(value);
	
	}
	
	/**
	 * The Signal Value as a Hex
	 * @return the Signal Value as a Hexadecimal Representation
	 */
	public String getValueAsHex() {
		
		return "0x" + (getValueAsLong() == 0 ? "00" : Hex.encodeHexString(value.toByteArray()).toUpperCase());
	
	}

	/**
	 * Convert the 
	 * @param bits
	 * @return
	 */
	private long convert(BitSet bits) {
		long value = 0L;
		for (int i = 0; i < bits.length(); ++i) {
			value += bits.get(i) ? (1L << i) : 0L;
		}
		return value;
	}
	
}

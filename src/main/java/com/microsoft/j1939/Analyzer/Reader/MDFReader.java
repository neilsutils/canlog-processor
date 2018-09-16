/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.microsoft.j1939.Analyzer.Reader;

import static com.microsoft.j1939.Analyzer.Util.OutputUtil.writeLine;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.math.BigInteger;
import java.util.LinkedList;
import java.util.List;
import java.util.Map.Entry;
import java.util.TreeMap;

import org.joda.time.DateTime;

import com.microsoft.j1939.Analyzer.Schema.Bus;
import com.microsoft.j1939.Analyzer.Schema.Message;
import com.microsoft.j1939.Analyzer.Schema.NetworkDefinition;

/**
 *
 * @author Neil Brittliff
 */
public class MDFReader {
	public interface MDFVisitor {

		boolean onEachRecord(long counter, DateTime dateTime, byte[] data, double clock, long id) throws IOException;

	}

	private RandomAccessFile mdfFile = null;
	private FileInputStream inputStream = null;
	private BufferedInputStream bufferedInputStream = null;
	private final byte[] U8 = new byte[1];
	private final byte[] U16 = new byte[2];
	private final byte[] U32 = new byte[4];
	private final byte[] U64 = new byte[8];
	public String Filename = null;
	public List<MDFVisitor> visitors = new LinkedList<MDFVisitor>();
	private final NetworkDefinition network;
	private final boolean debug;

	TreeMap<Long, Long> idMap = new TreeMap<Long, Long>();

	long iCounter = 0;
	long recordCount = 0;
	
	/**
	 * MDFReader Constructor
	 * @param network the Network for the DBC File
	 */
	public MDFReader(NetworkDefinition network) {
		this(network, false);
	}

	/**
	 * MDFReader Constructor
	 * @param network the Network for the DBC File
	 * @param debug - 'true' debugging is shown
	 */
	public MDFReader(NetworkDefinition network, boolean debug) {
		
		this.network = network;
		this.debug = debug;

	}

	/**
	 * Open the File
	 * 
	 * @param file
	 *            the File to Open
	 * @return 'tru'e file opened OK , false otherwise
	 * @throws IOException
	 */
	public boolean open(String file) throws IOException {
		try {
			mdfFile = new RandomAccessFile(file, "r");
			inputStream = new FileInputStream(mdfFile.getFD());
			bufferedInputStream = new BufferedInputStream(inputStream);
			return true;
		} catch (Exception e) {
			throw new IOException(e);
		}
	}

	/**
	 * Close the File
	 * 
	 * @throws IOException
	 */
	public void close() throws IOException {
		try {
			bufferedInputStream.close();
			inputStream.close();
			mdfFile.close();
		} catch (Exception e) {
			throw new IOException(e);
		}
	}

	/**
	 * Read the Number of Characters
	 * 
	 * @param len
	 *            the length to read
	 * @return a string of that many bytes
	 * 
	 * @throws IOException
	 *             thrown if the file cannot be read
	 */
	public final String readCharacters(int len) throws IOException {
		StringBuilder sb = new StringBuilder();

		byte[] data = new byte[len];
		if (bufferedInputStream.read(data) < 0) {
			return null;
		}
		for (byte b : data) {
			sb.append((char) b);
		}
		return sb.toString();
	}

	/**
	 * Read all the J1939 records
	 * 
	 * @param dateTime
	 *            Time Offset
	 * @param rawData
	 *            the Raw Data
	 * @param recordCount
	 *            the number of records
	 * @return true when completed
	 * @throws IOException
	 *             thrown if the file cannot be read
	 */
	public boolean readRecords(DateTime dateTime, byte[] rawData, long recordCount) throws IOException {

		iCounter = 0;
		this.recordCount = recordCount;
		
		while (iCounter < recordCount && readRecord(dateTime, iCounter, rawData, recordCount)) {
			iCounter += 1;
		}

		return true;

	}

	public boolean readRecord(DateTime dateTime, long iCounter, byte[] rawData, long recordCount) throws IOException {
		mdfFile.read(rawData);

		if (rawData[0] != 0x01 || rawData[1] != 0x00 || rawData[2] != 0x01 || rawData[3] != 0x00) {
			if (isClear(rawData)) {
			}
		}

		double clock = ((double) ((Byte.toUnsignedLong(rawData[22]) << 24) + (Byte.toUnsignedLong(rawData[21]) << 16)
				+ (Byte.toUnsignedLong(rawData[20]) << 8) + Byte.toUnsignedLong(rawData[19])));

		long id = ((Byte.toUnsignedLong(rawData[7]) << 24) + (Byte.toUnsignedLong(rawData[6]) << 16)
				+ (Byte.toUnsignedLong(rawData[5]) << 8) + Byte.toUnsignedLong(rawData[4])) & 0x1FFFFFFF;

		dateTime = dateTime.plusMillis((int) (clock / 1000));

		int dataLen = rawData[10];
		byte[] data = new byte[dataLen];
		System.arraycopy(rawData, 11, data, 0, dataLen);

		recordID(id);

		for (MDFVisitor visitor : visitors) {

			if (!visitor.onEachRecord(iCounter, dateTime, data, clock, id)) {
				return false;
			}
		}

		return true;

	}

	/**
	 * Seek to a position in the file
	 * 
	 * @param pos
	 *            the new position (if valid)
	 * @throws IOException
	 *             thrown if cannot be read
	 */
	public final void seek(long pos) throws IOException {
		
		mdfFile.seek(pos);

		bufferedInputStream = new BufferedInputStream(inputStream);
	}

	/**
	 * Read a Unsigned 8
	 * 
	 * @return the Unsigned 8 Integer (U8)
	 * @throws IOException
	 *             thrown if cannot be read
	 */
	public final int readU8() throws IOException {
		return (bufferedInputStream.read(U8) < 0) ? -1 : Byte.toUnsignedInt(U8[0]);
	}

	/**
	 * Read a Unsigned 16
	 * 
	 * @return the Unsigned 16 Integer (S16)
	 * @throws IOException
	 *             thrown if cannot be read
	 */
	public final int readU16I() throws IOException {
		if (bufferedInputStream.read(U16) < 0) {
			return -1;
		}
		return (Byte.toUnsignedInt(U16[1]) << 8) + Byte.toUnsignedInt(U16[0]);
	}

	/**
	 * Read a Signed 16
	 * 
	 * @return the Signed 16 Integer (S16)
	 * @throws IOException
	 *             thrown if cannot be read
	 */
	public final int readS16I() throws IOException {
		if (bufferedInputStream.read(U16) < 0) {
			return -1;
		}
		return (U16[1] << 8) + Byte.toUnsignedInt(U16[0]);
	}

	/**
	 * Read an unsigned integer (U32)
	 * 
	 * @return the unsigned integer
	 * @throws IOException
	 *             thrown if cannot be read
	 */
	public final long readU32I() throws IOException {
		if (bufferedInputStream.read(U32) < 0) {
			return -1;
		}
		return ((Byte.toUnsignedLong(U32[3]) << 24) + (Byte.toUnsignedLong(U32[2]) << 16)
				+ (Byte.toUnsignedLong(U32[1]) << 8) + Byte.toUnsignedLong(U32[0]));
	}

	/**
	 * Read Unsigned long (U64)
	 * 
	 * @return a long
	 * @throws IOException
	 *             thrown if cannot be read
	 */
	public final long readU64I() throws IOException {
		if (bufferedInputStream.read(U64) < 0) {
			return -1;
		}
		return (Byte.toUnsignedLong(U64[7]) << 56) + (Byte.toUnsignedLong(U64[6]) << 48)
				+ (Byte.toUnsignedLong(U64[5]) << 40) + (Byte.toUnsignedLong(U64[4]) << 32)
				+ (Byte.toUnsignedLong(U64[3]) << 24) + (Byte.toUnsignedLong(U64[2]) << 16)
				+ (Byte.toUnsignedLong(U64[1]) << 8) + Byte.toUnsignedLong(U64[0]);
	}

	/**
	 * Check to see if it is a valid records
	 * 
	 * @param data
	 *            the byte check
	 * @return 'true' if Binary Zero, 'false' otherwise
	 */
	private boolean isClear(byte[] data) {
		for (byte b : data) {
			if (b != 0x00) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Set the Identifier
	 * 
	 * @param id
	 *            the Packet's Identifier
	 */
	public final void recordID(long id) {

		if (!idMap.containsKey(id)) {
			idMap.put(id, 1L);
		} else {
			idMap.put(id, idMap.get(id) + 1);
		}

	}

	/**
	 * Summary output
	 * @throws IOException 
	 */
	public void summary(OutputStream outputStream) throws IOException {

		writeLine(outputStream, "Summary: ***");
		writeLine(outputStream, "");
		writeLine(outputStream, "   Counters");
		writeLine(outputStream, "	Records: " + recordCount);
		writeLine(outputStream, "	Counter: " + iCounter);
		writeLine(outputStream, "");
		
		writeLine(outputStream, "   IDs");

		for (Entry<Long, Long> entry : idMap.entrySet()) {
			writeLine(outputStream, "	" + entry.getKey() + " (" + "0x"
					+ BigInteger.valueOf(entry.getKey()).toString(16).toUpperCase() + ") - [" +  getName(entry.getKey()) + "] : "+ entry.getValue());
		}

		writeLine(outputStream, "***");

	}
	
	private String getName(long id) {
		for (Bus bus : network.getBus()) {

			for (Message message : bus.getMessage()) {

				if (message.getId().equals("0x" + BigInteger.valueOf(id).toString(16).toUpperCase())) {
					return message.getName();
				}
				
			}
			
		}
		
		return "";
		
	}

}

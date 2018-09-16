package com.microsoft.j1939.Analyzer.Blocks;

package com.microsoft.j1939.Analyzer.Blocks;

import static com.microsoft.j1939.Analyzer.Util.OutputUtil.writeLine;

import java.io.IOException;
import java.io.OutputStream;
import java.text.ParseException;
import java.util.Date;

import org.joda.time.DateTime;
import org.joda.time.format.DateTimeFormat;

import com.microsoft.j1939.Analyzer.Reader.MDFReader;

/**
 * HD BLock Interpreter
 *
 * @author Neil Brittliff
 * @see IDBlock
 *
 */
public class HDBlock {
	final IDBlock idBlock;
	public String headerIdentifier = null;
	public int blockSize = -1;
	public long DGBlock = -1;
	public long TXBlock = -1;
	public long PRBlock = -1;
	public int noDataGroups = 0;
	public String date = null;
	public String time = null;
	public String author = null;
	public String organisation = null;
	public String project = null;
	public String subject = null;
	public Date timeStamp = null;
	public int utcOffset = 0;
	public int timeQuality = 0;
	public String timeID = null;

	/**
	 * HDBlock Constructor
	 * 
	 * @param idBlock
	 *            the ID Block
	 */
	public HDBlock(IDBlock idBlock) {

		this.idBlock = idBlock;

	}

	/**
	 * MDF reader - read and interprets the HD Block
	 * 
	 * @param reader
	 *            the file Reader
	 * 
	 * @throws IOException
	 */
	public final void read(MDFReader reader) throws IOException {
		headerIdentifier = reader.readCharacters(2);
		blockSize = reader.readU16I();
		DGBlock = reader.readU32I();
		TXBlock = reader.readU32I();
		PRBlock = reader.readU32I();
		noDataGroups = reader.readU16I();
		date = reader.readCharacters(10);
		time = reader.readCharacters(8);
		author = reader.readCharacters(32);
		organisation = reader.readCharacters(32);
		project = reader.readCharacters(32);
		subject = reader.readCharacters(32);

		if (idBlock.Version >= 320) {
			timeStamp = new Date(reader.readU64I());
			utcOffset = reader.readS16I();
			timeQuality = reader.readU16I();
			timeID = reader.readCharacters(32);
		}

	}

	public DateTime getDateTime() throws ParseException {
		return DateTime.parse(date.trim() + " " + time, DateTimeFormat.forPattern("dd:MM:YYYY HH:mm:ss"));
	}

    /**
     * Write out a summary of the Blocks
     * @param os the output stream
     * @throws IOException
     */
    public final void debug(OutputStream os) throws IOException {
    	writeLine(os, headerIdentifier + " Block");
    	writeLine(os, "   Block Size:  " + blockSize);
    	writeLine(os, "   DG Block:    " + DGBlock);
    	writeLine(os, "   TX Block:    " + TXBlock);
    	writeLine(os, "   PR Block:    " + PRBlock);
    	writeLine(os, "   Data blocks: " + noDataGroups);
    	writeLine(os, "   Date:        " + date);
    	writeLine(os, "   Time:        " + time);
    	writeLine(os, "   Author:      " + "'" + (author.replaceAll("[^\\dA-Za-z ]", "").replaceAll("\\s+", "+")) + "'");
    	writeLine(os, "   Organisation:" + "'" + (organisation.replaceAll("[^\\dA-Za-z ]", "").replaceAll("\\s+", "+")) + "'");
    	writeLine(os, "   Project:     " + "'" + (project.replaceAll("[^\\dA-Za-z ]", "").replaceAll("\\s+", "+")) + "'");
    	writeLine(os, "   Subject:     " + "'" + (subject.replaceAll("[^\\dA-Za-z ]", "").replaceAll("\\s+", "+")) + "'");

		if (timeStamp != null) {
			writeLine(os, "   Time stamp:  " + timeStamp);
			writeLine(os, "   UTC offset:  " + utcOffset);
			writeLine(os, "   Time quality:" + timeQuality);
			writeLine(os, "   Timer ID:    " + timeID);
		}
		
	}
    
}
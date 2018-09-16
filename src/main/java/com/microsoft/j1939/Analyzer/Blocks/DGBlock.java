p/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.microsoft.j1939.Analyzer.Blocks;

import static com.microsoft.j1939.Analyzer.Util.OutputUtil.writeLine;

import java.io.IOException;
import java.io.OutputStream;

import com.microsoft.j1939.Analyzer.Reader.MDFReader;

/**
 * DG Block 
 * @author Dr. Neil Brittliff
 */
public class DGBlock {
    
    public String HeaderIdentifier = null;
    public int BlockSize = -1;
    public long DGBlock = -1;
    public long CGBlock = -1;
    public long TRBlock = -1;
    public long DataBlock = -1;
    public int noChannelGroups = -1;
    public int noRecordIDs = -1;
    
    /**
     * Read the Block
     * @param reader the File Reader for the CAM Log
     * @throws IOException
     */
    public final void read(MDFReader reader) throws IOException {
        HeaderIdentifier = reader.readCharacters(2);
        BlockSize = reader.readU16I();
        DGBlock = reader.readU32I();
        CGBlock = reader.readU32I();
        TRBlock = reader.readU32I();
        DataBlock = reader.readU32I();
        noChannelGroups = reader.readU16I();
        noRecordIDs = reader.readU16I();
    }

    /**
     * Write out a summary of the Blocks
     * @param os the output stream
     * @throws IOException
     */
    public final void debug(OutputStream os) throws IOException {
    	writeLine(os, HeaderIdentifier+" Block");
    	writeLine(os, "   Block Size: "+BlockSize);
    	writeLine(os, "   DG Block:   "+DGBlock);
    	writeLine(os, "   CG Block:   "+CGBlock);
    	writeLine(os, "   TR Block:   "+TRBlock);
    	writeLine(os, "   Data Block: "+DataBlock);
    	writeLine(os, "   No. Channel Groups:  "+noChannelGroups);
    	writeLine(os, "   No. Records:   "+noRecordIDs);
    }
    
}

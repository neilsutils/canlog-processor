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

public class CGBlock {
    public final IDBlock idBlock;
    public String HeaderIdentifier = null;
    public int BlockSize = -1;
    public long CGNBlock = -1;
    public long CNBlock = -1;
    public long TXBlock = -1;
    public int RecordID = -1;
    public int ChannelCount = -1;
    public int SizeOfDataRecord = -1;
    public long recordCount = -1;
    public long SRBlock = -1;
    
    /**
     * The CGBlock constructor
     * @param idBlock the ID Block
     */
    public CGBlock(IDBlock idBlock) {
    	
    	this.idBlock = idBlock;
    	
    }
    
    /**
     * Read the Block
     * @param reader the File Reader for the CAM Log
     * @throws IOException
     */
    public final void read(MDFReader reader) throws IOException {
        HeaderIdentifier = reader.readCharacters(2);
        BlockSize = reader.readU16I();
        CGNBlock = reader.readU32I();
        CNBlock = reader.readU32I();
        TXBlock = reader.readU32I();
        RecordID = reader.readU16I();
        ChannelCount = reader.readU16I();
        SizeOfDataRecord = reader.readU16I();
        recordCount = reader.readU32I();
        
        if (idBlock.Version >= 330) {
            SRBlock = reader.readU32I();
        }
        
    }

    /**
     * Write out a summary of the Blocks
     * @param os the output stream
     * @throws IOException
     */
    public final void debug(OutputStream os) throws IOException {
        
    	writeLine(os, HeaderIdentifier+" Block");
        writeLine(os, "   Block Size: "+BlockSize);
        writeLine(os, "   CG Next:    "+CGNBlock);
        writeLine(os, "   CN Block:   "+CNBlock);
        writeLine(os, "   TR Block:   "+TXBlock);
        writeLine(os, "   Record ID:  "+RecordID);
        writeLine(os, "   Chan. count: "+ChannelCount);
        writeLine(os, "   Rec. size:  "+SizeOfDataRecord);
        writeLine(os, "   Rec. count: "+recordCount);
        writeLine(os, "   SR Block:   "+SRBlock);
        
    }
}

/*
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
 *
 * @author Dr. Neil Brittliff
 */
public class CNBlock {
    
    public enum ChannelType { DATA, TIME }
    public enum DataType { UNSIGNED, SIGNED, FLOAT, DOUBLE, STRING, BYTEARRAY, 
                           UNSIGNED_BE, SIGNED_BE, FLOAT_BE, DOUBLE_BE,
                           UNSIGNED_LE, SIGNED_LE, FLOAT_LE, DOUBLE_LE}
    
    public String HeaderIdentifier = null;
    public int blockSize = -1;
    public long CNBlock = -1;
    public long CCBlock = -1;
    public long CEBlock = -1;
    public long CDBlock = -1;
    public ChannelType channelType = ChannelType.DATA;
    public String name = null;
    public String description = null;
    public int offset = -1;
    public int bitSize = -1;
    public DataType dataType = DataType.UNSIGNED;
    
    /**
     * Read the Block
     * @param reader the File Reader for the CAM Log
     * @throws IOException
     */
    public final void read(MDFReader R) throws IOException {
        HeaderIdentifier = R.readCharacters(2);
        blockSize = R.readU16I();
        CNBlock = R.readU32I();
        CCBlock = R.readU32I();
        CEBlock = R.readU32I();
        CDBlock = R.readU32I();
        channelType = (R.readU16I() == 0) ? ChannelType.DATA : ChannelType.TIME;
        name  = R.readCharacters(32);
        description  = R.readCharacters(128);
        offset = R.readU16I();
        bitSize = R.readU16I();
        int type = R.readU16I();
        switch (type) {
            case 0: dataType = DataType.UNSIGNED; break;
            case 1: dataType = DataType.SIGNED; break;
            case 2: dataType = DataType.FLOAT; break;
            case 3: dataType = DataType.DOUBLE; break;
            case 7: dataType = DataType.STRING; break;
            case 8: dataType = DataType.BYTEARRAY; break;
            case 9: dataType = DataType.UNSIGNED_BE; break;
            case 10: dataType = DataType.SIGNED_BE; break;
            case 11: dataType = DataType.FLOAT_BE; break;
            case 12: dataType = DataType.DOUBLE_BE; break;
            case 13: dataType = DataType.UNSIGNED_LE; break;
            case 14: dataType = DataType.SIGNED_LE; break;
            case 15: dataType = DataType.FLOAT_LE; break;
            case 16: dataType = DataType.DOUBLE_LE; break;
        }
    }

    /**
     * Write out a summary of the Blocks
     * @param os the output stream
     * @throws IOException
     */
    public final void debug(OutputStream os) throws IOException {
        writeLine(os, HeaderIdentifier+" Block ***");
        writeLine(os, "   Block Size: " + blockSize);
        writeLine(os, "   CN Block:   " + CNBlock);
        writeLine(os, "   CC Block:   " + CCBlock);
        writeLine(os, "   CE Block:   " + CEBlock);
        writeLine(os, "   CD Block:   " + CDBlock);
        writeLine(os, "   Chan. type: " + channelType);
        writeLine(os, "   Name:       '"+ (name.replaceAll("[^\\dA-Za-z ]", "").replaceAll("\\s+", "+") + "'"));
        writeLine(os, "   Description:'" + (description.replaceAll("[^\\dA-Za-z ]", "").replaceAll("\\s+", "+") + "'"));
        writeLine(os, "   Offset:     " + offset);
        writeLine(os, "   BitSize:    " + bitSize);
        writeLine(os, "   Data type:  " + dataType);
        writeLine(os, "***");
               
    }
}

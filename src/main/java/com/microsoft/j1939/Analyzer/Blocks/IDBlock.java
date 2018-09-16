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


public class IDBlock {
    public enum ByteOrder { INTEL, MOTOROLA }
    public enum FloatType { IEEE754, GFLOAT, DFLOAT }
    
    public String FileIdentifier = null;
    public String FormatIdentifier = null;
    public String ProgramIdentifier = null;
    public ByteOrder Order = ByteOrder.INTEL; 
    public FloatType Float = FloatType.IEEE754;
    public int Version = -1;
    public int CodePage = -1;
    public boolean UpToDateCGBlock = false;
    public boolean UpToDateSRBlock = false;
    
	/**
	 * MDF reader - read and interprets the HD Block
	 * 
	 * @param reader
	 *            the file Reader
	 * 
	 * @throws IOException
	 */
   public final void read(MDFReader reader) throws IOException {
        FileIdentifier = reader.readCharacters(8);
        FormatIdentifier = reader.readCharacters(8);
        ProgramIdentifier = reader.readCharacters(8);
        Order = (reader.readU16I() == 0) ? ByteOrder.INTEL : ByteOrder.MOTOROLA;
        
        int ft = reader.readU16I();
        Float = (ft == 1) ? FloatType.GFLOAT : (ft == 2) ? FloatType.DFLOAT : FloatType.IEEE754;
        Version = reader.readU16I();
        CodePage = reader.readU16I();
        reader.readCharacters(2 + 26);   // Reserved
        int flags = reader.readU16I();
        UpToDateCGBlock = (flags & 0x00000001) == 0;
        UpToDateSRBlock = (flags & 0x00000002) == 0;
        flags = reader.readU16I();       // Custom flags
    }

    /**
     * Write out a summary of the Blocks
     * @param os the output stream
     * @throws IOException
     */
    public final void debug(OutputStream os) throws IOException {
    	writeLine(os, "ID Block");
    	writeLine(os, "   File:      " + FileIdentifier);
    	writeLine(os, "   Format:    " + FormatIdentifier);
    	writeLine(os, "   Program:   " + ProgramIdentifier);
    	writeLine(os, "   Order:     " + Order);
    	writeLine(os, "   Float:     " + Float);
    	writeLine(os, "   Version:   " + Version);
    	writeLine(os, "   Code Page: " + CodePage);
    	writeLine(os, "   Flags:");
    	writeLine(os, "      CG Block up to date: " + UpToDateCGBlock);
    	writeLine(os, "      SR Block up to date: " + UpToDateSRBlock);
    }
    
}

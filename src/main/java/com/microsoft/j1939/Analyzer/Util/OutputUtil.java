package com.microsoft.j1939.Analyzer.Util;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.Charset;

public class OutputUtil {

	/**
	 * Write to an outputStream
	 * @param outputStream the output stream
	 * @param line the line to write out
	 * 
	 * @throws IOException
	 */
	static public void writeLine(OutputStream outputStream, String line) throws IOException {
		
		outputStream.write((line + "\r\n").getBytes(Charset.forName("UTF-8")));
		
	}
	
}

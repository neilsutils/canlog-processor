package com.microsoft.j1939.Analyzer.Builder;

import java.io.Closeable;
import java.io.IOException;
import java.util.List;

import net.sourceforge.argparse4j.inf.Namespace;

public interface OutputBuilder extends Closeable {

	void open(Namespace ns, List<String> headers) throws IOException;
	void write(List<String> record) throws IOException;
	
}

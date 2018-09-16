package com.microsoft.j1939.Analyzer.Builder;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.util.List;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVPrinter;

import net.sourceforge.argparse4j.inf.Namespace;

public class CsvBuilder implements OutputBuilder {
	BufferedWriter writer;
	CSVPrinter csvPrinter;
	
	@Override
	public
	void open(Namespace ns, List<String> headers) throws IOException{
		
		writer = new BufferedWriter(new FileWriter(ns.getString("output")));
		csvPrinter = new CSVPrinter(writer, CSVFormat.DEFAULT.withHeader(headers.toArray(new String[0])));

	}

	@Override
	public void write(List<String> record) throws IOException {
		csvPrinter.printRecord(record);
		csvPrinter.flush();

	}

	@Override
	public void close() throws IOException {
		csvPrinter.close();
	}

}

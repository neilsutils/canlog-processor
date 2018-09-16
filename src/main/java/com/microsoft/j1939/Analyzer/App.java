package com.microsoft.j1939.Analyzer;

import static com.microsoft.j1939.Analyzer.Util.OutputUtil.writeLine;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.text.ParseException;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.TreeMap;

import org.apache.commons.lang3.mutable.MutableObject;
import org.joda.time.DateTime;

import com.microsoft.j1939.Analyzer.Blocks.CGBlock;
import com.microsoft.j1939.Analyzer.Blocks.CNBlock;
import com.microsoft.j1939.Analyzer.Blocks.DGBlock;
import com.microsoft.j1939.Analyzer.Blocks.HDBlock;
import com.microsoft.j1939.Analyzer.Blocks.IDBlock;
import com.microsoft.j1939.Analyzer.Builder.CsvBuilder;
import com.microsoft.j1939.Analyzer.Builder.OutputBuilder;
import com.microsoft.j1939.Analyzer.Builder.ParquetBlobBuilder;
import com.microsoft.j1939.Analyzer.Builder.ParquetFileBuilder;
import com.microsoft.j1939.Analyzer.Packet.Packet;
import com.microsoft.j1939.Analyzer.Packet.Transmission;
import com.microsoft.j1939.Analyzer.Parser.DbcParser;
import com.microsoft.j1939.Analyzer.Reader.MDFReader;
import com.microsoft.j1939.Analyzer.Reader.MDFReader.MDFVisitor;
import com.microsoft.j1939.Analyzer.Schema.Bus;
import com.microsoft.j1939.Analyzer.Schema.Message;
import com.microsoft.j1939.Analyzer.Schema.NetworkDefinition;
import com.microsoft.j1939.Analyzer.Schema.Signal;

import net.sourceforge.argparse4j.ArgumentParsers;
import net.sourceforge.argparse4j.inf.ArgumentParser;
import net.sourceforge.argparse4j.inf.ArgumentParserException;
import net.sourceforge.argparse4j.inf.Namespace;

/**
 * Analyzes a CAN (Controlled Area Network) Log by applying a Schema
 *
 */
public class App {
	List<String> csvHeaders = new LinkedList<String>();

	Map<String, OutputBuilder> writers = new HashMap<String, OutputBuilder>();
	final String sep = "_";

	App() throws IOException {
		writers.put("csv-file", new CsvBuilder());
		writers.put("parquet-file", new ParquetFileBuilder());
		writers.put("parquet-blob", new ParquetBlobBuilder());
	}
	
	App(Namespace ns) throws ParseException, IOException {
		this();
		
		long start = System.currentTimeMillis();

		List<CNBlock> cnBlocks = new LinkedList<CNBlock>();

		csvHeaders.add("TimeStamp");
		csvHeaders.add("Clock");

		System.out.println("Parameters: ***");
		System.out.println("	Cam Log: '" + ns.getString("file") + "'");
		System.out.println("	Schema: '" + ns.getString("schema") + "'");
		System.out.println("	Log: '" + ns.getString("log") + "'");
		System.out.println("	Output: '" + ns.getString("output") + "'");
		System.out.println("	Format: '" + ns.getString("format") + "'");
		System.out.println();

		OutputBuilder outputBuilder = writers.get(ns.getString("format"));
		
		OutputStream log = ns.getString("log").equals("stdout") ? System.out
				: new FileOutputStream(ns.getString("log"));

		final DbcParser parser = new DbcParser();

		parser.parseFile(new File(ns.getString("schema")), System.out);

		final Map<String, Message> messageMap = new HashMap<String, Message>();

		writeLine(log, "Load Report ***");
		writeLine(log, "     Date: " + (new Date()).toString());
		writeLine(log, "     Developed by Microsoft Pty Ltd in Omni");
		writeLine(log, "");

		writeLine(log, "Messages: ***");
		for (Bus bus : parser.getNetwork().getBus()) {

			for (Message message : bus.getMessage()) {
				writeLine(log, "      [" + message.getId() + "] - '" + message.getName() + "'");
				writeLine(log, "      Signals: ");
				messageMap.put(message.getId(), message);

				for (Signal signal : message.getSignal()) {
					csvHeaders.add(message.getName() + sep + signal.getName());

					writeLine(log, "      		(" + signal.getName() + ")"
							+ (signal.getNotes() != null ? " - '" + signal.getNotes() + "'" : ""));

				}

				writeLine(log, "");

			}

		}

		// Setup the CSV Reader
		
		outputBuilder.open(ns, csvHeaders);
		
		List<String> emptyRecord = new LinkedList<String>();

		for (int iSize = 0; iSize < csvHeaders.size(); iSize++) {
			emptyRecord.add("");
		}

		// Process the CAN Blocks
		MDFReader reader = new MDFReader(parser.getNetwork());
		reader.open(ns.getString("file"));

		// Process the IDBlock which points to the other Blocks
		IDBlock idBlock = new IDBlock();

		idBlock.read(reader);
		idBlock.debug(log);

		// Process the HDBlock information and pointers
		HDBlock hdBlock = new HDBlock(idBlock);

		hdBlock.read(reader);
		hdBlock.debug(log);

		reader.seek(hdBlock.DGBlock);

		DGBlock dgBlock = new DGBlock();

		dgBlock.read(reader);
		dgBlock.debug(log);

		if (dgBlock.CGBlock != -1) {
			reader.seek(dgBlock.CGBlock);

			CGBlock cgBlock = new CGBlock(idBlock);

			cgBlock.read(reader);
			cgBlock.debug(log);

			if (cgBlock.CNBlock != -1) {
				long cnBlockPtr = cgBlock.CNBlock;
				while (cnBlockPtr > 0) {
					reader.seek(cnBlockPtr);

					CNBlock cnBlock = new CNBlock();
					cnBlock.read(reader);

					cnBlocks.add(cnBlock);
					cnBlock.debug(log);

					cnBlockPtr = cnBlock.CNBlock;

				}

			}

			byte[] rawData = new byte[dgBlock.noRecordIDs + cgBlock.SizeOfDataRecord];
			final long totalRecords = cgBlock.recordCount;

			writeLine(log, "");
			writeLine(log, "Processing: ***");

			writeLine(log, "	Date: '" + hdBlock.getDateTime().toString() + "'");
			writeLine(log, "	Length: '" + dgBlock.noRecordIDs + cgBlock.SizeOfDataRecord + "'");
			writeLine(log, "	Records: '" + totalRecords + "'");
			writeLine(log, "");

			final Map<Long, Long> idMap = new TreeMap<Long, Long>();
			final Map<String, Map<String, List<Long>>> signalMap = new TreeMap<String, Map<String, List<Long>>>();

			final MutableObject<DateTime> startTime = new MutableObject<DateTime>(null);
			final MutableObject<DateTime> stopTime = new MutableObject<DateTime>(new DateTime());

			// Utilizing the Visitor Design Pattern to process each record
			reader.seek(dgBlock.DataBlock);
			reader.visitors.add(new MDFVisitor() {

				public boolean onEachRecord(long counter, DateTime dateTime, byte[] data, double clock, long id)
						throws IOException {
					Packet packet = new Packet(messageMap, counter, dateTime, clock, id, data);

					if (counter % 1000 == 0 && counter != 0) {
						float proportion = (float) counter / totalRecords;

						System.out.println((new Date()).toString() + " - Processed: '" + counter + "' - "
								+ String.format("%.04f", (proportion * 100)) + "%");

					}

					if (startTime.getValue() == null) {
						startTime.setValue(packet.getTimeStamp());
					}

					stopTime.setValue(packet.getTimeStamp());

					final List<String> record = new LinkedList<String>(emptyRecord);

					record.set(0, packet.getTimeStamp().toString());
					record.set(1, Double.toString(clock / 1000));

					if (packet.getMessage() != null) {

						for (Transmission event : packet.getTransmissions()) {
							record.add(
									csvHeaders
											.indexOf(packet.getMessage().getName() + sep + event.getSignal().getName()),
									Long.toString(event.getValueAsLong()));

						}

					}

					outputBuilder.write(record);

					if (!idMap.containsKey(packet.getId())) {

						if (packet.getTransmissions() != null) {
							signalMap.put(packet.getMessage().getName(), new TreeMap<String, List<Long>>());
						}

						idMap.put(packet.getId(), 1L);

					} else {

						idMap.put(packet.getId(), idMap.get(packet.getId()) + 1);

					}

					if (packet.getTransmissions() != null) {
						for (Transmission event : packet.getTransmissions()) {
							if (!signalMap.get(packet.getMessage().getName())
									.containsKey(event.getSignal().getName())) {
								List<Long> values = new LinkedList<Long>();
								values.add(1L);
								values.add(event.getValueAsLong());
								values.add(event.getValueAsLong());

								signalMap.get(packet.getMessage().getName()).put(event.getSignal().getName(), values);
							} else {
								List<Long> values = signalMap.get(packet.getMessage().getName())
										.get(event.getSignal().getName());

								values.set(0, values.get(0) + 1);
								values.set(1, Math.min(event.getValueAsLong(), values.get(1)));
								values.set(2, Math.max(event.getValueAsLong(), values.get(2)));

								signalMap.get(packet.getMessage().getName()).put(event.getSignal().getName(), values);

							}

						}
					}

					return true;
				}

			});

			reader.readRecords(hdBlock.getDateTime(), rawData, totalRecords);


			writeLine(log, "Coverage: ***");
			writeLine(log, "	Start: '" + startTime.getValue().toString() + "'");
			writeLine(log, "	Stop: '" + stopTime.getValue().toString() + "'");
			writeLine(log, "***");
			writeLine(log, "");

			// Idea of the message structure
			for (Entry<Long, Long> entry : idMap.entrySet()) {
				writeLine(log,
						"	" + entry.getKey() + " (" + "0x"
								+ BigInteger.valueOf(entry.getKey()).toString(16).toUpperCase() + ") - ["
								+ getName(parser.getNetwork(), entry.getKey()) + "] : " + entry.getValue());
			}

			writeLine(log, "***");
			writeLine(log, "");

			writeLine(log, "Signal Summary: ");

			for (Entry<String, Map<String, List<Long>>> entry : signalMap.entrySet()) {
				writeLine(log, "	" + entry.getKey());

				for (Entry<String, List<Long>> value : entry.getValue().entrySet()) {
					writeLine(log, "		" + value.getKey() + " - " + value.getValue().get(0) + " : "
							+ value.getValue().get(1) + " : " + value.getValue().get(2));

				}

				writeLine(log, "");

			}

		}

		System.out.println((new Date()).toString() + " - Closing Output");

		outputBuilder.close();

		// Statistics Report
		System.out.println("Stats: ***");
		System.out.println("	Taken: '" + ((System.currentTimeMillis() - start) / 1000) + "' (seconds)");
		System.out.println("***");
		System.out.println("");
		
		reader.summary(log);

		log.close();

	}

	/**
	 * Get the Message for the ID
	 * 
	 * @param network
	 * @param id
	 * @return
	 */
	private String getName(NetworkDefinition network, long id) {
		for (Bus bus : network.getBus()) {

			for (Message message : bus.getMessage()) {

				if (message.getId().equals("0x" + BigInteger.valueOf(id).toString(16).toUpperCase())) {
					return message.getName();
				}

			}

		}

		return "";

	}

	/**
	 * The Main procedure
	 * 
	 * @param args
	 *            the input arguments
	 * @throws ParseException
	 */
	public static void main(String[] args) throws ParseException {
		ArgumentParser parser = ArgumentParsers.newFor("App").build().defaultHelp(true)
				.description("Processes a CAM J1939 Parser");
		
		parser.addArgument("-s", "--schema").help("Specify the schema for the parser to use to use");
		
		parser.addArgument("-o", "--output").help("The csv file");
		
		parser.addArgument("-l", "--log").setConst("stdout")
		.help("If specified - the print summary goes to a file otherwise 'stdout'").setDefault("stdout");
		
		parser.addArgument("-f", "--format").setConst("csv", "parquet")
		.help("The output format").setDefault("csv");

		parser.addArgument("file").help("CAM file to process");

		try {
			new App(parser.parseArgs(args));
		} catch (ArgumentParserException e) {
			parser.handleError(e);
			System.exit(1);
		} catch (IOException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}

	}
}

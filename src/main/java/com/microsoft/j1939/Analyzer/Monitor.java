package com.microsoft.j1939.Analyzer;

import static com.microsoft.j1939.Analyzer.Util.OutputUtil.writeLine;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLStreamHandler;
import java.security.InvalidKeyException;
import java.text.ParseException;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.TreeMap;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.mutable.MutableObject;
import org.joda.time.DateTime;
import org.json.JSONArray;
import org.json.JSONObject;

import com.microsoft.azure.storage.CloudStorageAccount;
import com.microsoft.azure.storage.StorageException;
import com.microsoft.azure.storage.blob.CloudBlobClient;
import com.microsoft.azure.storage.blob.CloudBlobContainer;
import com.microsoft.azure.storage.blob.CloudBlockBlob;
import com.microsoft.azure.storage.queue.CloudQueue;
import com.microsoft.azure.storage.queue.CloudQueueClient;
import com.microsoft.azure.storage.queue.CloudQueueMessage;
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

public class Monitor {

	List<String> csvHeaders = new LinkedList<String>();
	OutputStream log;
	
	Map<String, OutputBuilder> writers = new HashMap<String, OutputBuilder>();
	final String sep = "_";
	
	public static final String storageConnectionString = "DefaultEndpointsProtocol=https;"
			+ "AccountName=[ACCOUNT_NAME];" + "AccountKey=[ACCOUNT_KEY];" + "EndpointSuffix=core.windows.net";
	public String uriConnection = "wasb://[CONTAINER_NAME]@[ACCOUNT_NAME]/[BLOB_NAME]?key=[ACCOUNT_KEY]";
	
	Monitor() throws IOException {
		writers.put("csv-file", new CsvBuilder());
		writers.put("parquet-file", new ParquetFileBuilder());
		writers.put("parquet-blob", new ParquetBlobBuilder());
		
		URL.setURLStreamHandlerFactory(protocol -> "wasb".equals(protocol) ? new URLStreamHandler() {
		    protected URLConnection openConnection(URL url) throws IOException {
		        return new URLConnection(url) {
		            public void connect() throws IOException {
		                throw new IOException("Not Supported");
		            }
		        };
		    }
		} : null);
	}
	
	Monitor(Namespace ns) throws ParseException, IOException {
		this();
		
		log = ns.getString("log").equals("stdout") ? System.out
				: new FileOutputStream(ns.getString("log"));

		
		System.out.println("Parameters: ***");
 		System.out.println("	Schema: '" + ns.getString("schema") + "'");
		System.out.println("	Log: '" + ns.getString("log") + "'");
		System.out.println("	Format: '" + ns.getString("format") + "'");
		System.out.println("	Queue: '" + ns.getString("queue") + "'");
		System.out.println();
			
		try {
		    String connection = String.format("DefaultEndpointsProtocol=https;AccountName=%s;AccountKey=%s;EndpointSuffix=core.windows.net",
		    		ns.getString("account"), ns.getString("key"));

		    // Retrieve storage account from connection-string.
		    CloudStorageAccount storageAccount =
		       CloudStorageAccount.parse(connection);
		    
		    CloudQueueClient queueClient = storageAccount.createCloudQueueClient();

		    CloudQueue queue = queueClient.getQueueReference(ns.getString("queue"));
		    queue.setShouldEncodeMessage(false);
		    
		    queue.createIfNotExists();
		    // Peek at the next message.
		    
		    CloudQueueMessage message = queue.retrieveMessage();

		    if (message == null) {
		    	System.out.println("*** No messages ***");
		    	writeLine(log, "*** No messages ***");
		    }
		    
		    // Output the message value.
		    while (message != null) {
			    JSONObject json = new JSONObject(new String(message.getMessageContentAsByte(), "utf-8"));
			    
		    	System.out.println("Found Message");

			    writeLine(log, "Processing: ");
			    writeLine(log, json.toString(4));
			    
			    process(ns, json);
			    
			    queue.deleteMessage(message);
			    
			    message = queue.retrieveMessage();
			    
		    }
		    
		   
		} catch (Exception e) {
		    e.printStackTrace();
		} finally {
		}
		
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
	
	private static CloudBlockBlob getBlobReference(String accountName, String key, String containerName, String blobName) throws URISyntaxException, StorageException, InvalidKeyException {
		String connectionString = StringUtils.replace(storageConnectionString, "[ACCOUNT_NAME]", accountName);
		connectionString = StringUtils.replace(connectionString, "[ACCOUNT_KEY]", key);
		
		System.out.println("Connection String: '" + connectionString + "'");
		System.out.println("Container: '" + containerName + "'");

		CloudStorageAccount account = CloudStorageAccount.parse(connectionString);

		CloudBlobClient blobClient  = account.createCloudBlobClient();
		CloudBlobContainer container = blobClient.getContainerReference(containerName);
		container.createIfNotExists();

		return container.getBlockBlobReference(blobName);

	}
	
	private void process(Namespace ns, JSONObject json) throws IOException, ParseException, InvalidKeyException, URISyntaxException, StorageException {
	
		long start = System.currentTimeMillis();

		List<CNBlock> cnBlocks = new LinkedList<CNBlock>();

		csvHeaders.add("TimeStamp");
		csvHeaders.add("Clock");
		
		String folder =  json.getString("blob_name").replace(json.getString("file_name"), "");
		
		String outputName =  folder  + "canlog.parquet"; 
		String summaryName =  folder  + "summary.json"; 
		String containerName = json.getString("container_name"); 
		String accountName = json.getString("account_name"); 
		String blobName = json.getString("blob_name"); 
		
		System.out.println("Folder: " + folder);
		System.out.println("	Output: '" +  outputName + "'");

		OutputBuilder outputBuilder = writers.get(ns.getString("format"));
		

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
		
		String connectionUrl = uriConnection.replace("[ACCOUNT_NAME]", accountName).
											 replace("[CONTAINER_NAME]", containerName).
											 replace("[BLOB_NAME]", outputName).
											 replace("[ACCOUNT_KEY]", ns.getString("key"));
		System.out.println("[Open] Connection URL:" + connectionUrl);
				
	
		outputBuilder.open(connectionUrl, csvHeaders);
		
		System.out.println("[Opened] Connection URL:" + connectionUrl);
		
		List<String> emptyRecord = new LinkedList<String>();

		for (int iSize = 0; iSize < csvHeaders.size(); iSize++) {
			emptyRecord.add("");
		}
		System.out.println("[Opened] Copy Blob");

		// Process the CAN Blocks
		MDFReader reader = new MDFReader(parser.getNetwork());
		
		CloudBlockBlob canlogBlob = getBlobReference(accountName, ns.getString("key"), containerName, blobName);
		
		File canFile = File.createTempFile("can", "log");
		
		canFile.deleteOnExit();
		
		canlogBlob.downloadToFile(canFile.getAbsolutePath());
		reader.open(canFile.getPath());	

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

			json.put("status", "processed");
			
			JSONObject completedJSON = complete(json, signalMap, outputName, ns.get("format"), startTime.getValue(), 
					                                  stopTime.getValue(), ((System.currentTimeMillis() - start)));

			System.out.println(completedJSON.toString(4));
		
			
			CloudBlockBlob summaryBlob = getBlobReference(accountName, ns.getString("key"), containerName, summaryName);
			String jsonDump = completedJSON.toString(4);
			
			summaryBlob.uploadFromByteArray(jsonDump.getBytes("UTF-8"), 0, jsonDump.length());
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
	 * Get a JSON Object
	 * @throws IOException 
	 */
	public JSONObject complete(JSONObject json, Map<String, Map<String, List<Long>>> signalMap, String outputName, String format, DateTime startTime, DateTime stopTime, long timeTaken) throws IOException {
		JSONObject summary = new JSONObject();
		json.append("run-log", summary);
		
		summary.put("Start-time", startTime.toString());
		summary.put("Stop-time", stopTime.toString());
		
		summary.put("Time-taken", timeTaken);
		summary.put("Output", outputName);
		summary.put("Format", format);
		
		JSONArray signals = new JSONArray();
		for (Entry<String, Map<String, List<Long>>> entry : signalMap.entrySet()) {
			JSONArray subSignals = new JSONArray();
			for (Entry<String, List<Long>> value : entry.getValue().entrySet()) {
				JSONObject signal = new JSONObject();
				signal.put("signal", value.getKey());
				signal.put("count", value.getValue().get(0));
				signal.put("min", value.getValue().get(1));
				signal.put("max", value.getValue().get(2));
				subSignals.put(signal);
			}
			
			JSONObject subClass = new JSONObject();
			subClass.put(entry.getKey(), subSignals);
			signals.put(subClass);

		}

		json.put("signals", signals);
		
		return json;
				
	}
		
	/**
	 * The Main procedure
	 * 
	 * @param args
	 *            the input arguments
	 * @throws ParseException
	 */
	public static void main(String[] args) {
		ArgumentParser parser = ArgumentParsers.newFor("Monitor").build().defaultHelp(true)
				.description("Processes a CAM J1939 Parser");
		
		parser.addArgument("-s", "--schema").help("Specify the schema for the parser to use to use");
		
		parser.addArgument("-a", "--account").help("The account's name");
		
		parser.addArgument("-k", "--key").help("The account's key");
		
		parser.addArgument("-l", "--log").setConst("stdout")
		.help("If specified - the print summary goes to a file otherwise 'stdout'").setDefault("stdout");
		
		parser.addArgument("-f", "--format").setConst("csv", "parquet")
		.help("The output format").setDefault("csv");

		parser.addArgument("queue").help("queue to process");

		try {
			new Monitor(parser.parseArgs(args));
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
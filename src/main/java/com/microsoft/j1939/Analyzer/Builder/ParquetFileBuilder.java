package com.microsoft.j1939.Analyzer.Builder;

import static com.microsoft.j1939.Analyzer.IO.OutputParquetFile.getOutputFile;

import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import org.apache.avro.Schema;
import org.apache.avro.SchemaBuilder;
import org.apache.avro.SchemaBuilder.FieldAssembler;
import org.apache.avro.generic.GenericData;
import org.apache.hadoop.conf.Configuration;
import org.apache.parquet.avro.AvroParquetWriter;
import org.apache.parquet.hadoop.ParquetWriter;
import org.apache.parquet.hadoop.metadata.CompressionCodecName;

import net.sourceforge.argparse4j.inf.Namespace;

public class ParquetFileBuilder implements OutputBuilder {
	ParquetWriter<GenericData.Record> writer;
	Schema parsedSchema;
	List<String> headers;
	
	public ParquetFileBuilder() throws IOException {
	}

	@Override
	public void close() throws IOException {
		
		writer.close();
	
	}
	
	@Override
	public void open(Namespace ns, List<String> headers) throws IOException {	
		
		open(ns.getString("output"), headers);
		
    }
	
	@Override
	public void open(String pathName, List<String> headers) throws IOException {	
		
		this.headers = headers;
		
	    Path path = FileSystems.getDefault().getPath(pathName);
	    Files.deleteIfExists(path);
	
		FieldAssembler<Schema> builder = SchemaBuilder.record("log").namespace("org.apache.avro.ipc").fields();

		for (String header : headers) {
			builder = builder.name(header).type().nullable().stringType().noDefault();
		}
		
		parsedSchema = builder.endRecord();
		
		writer = AvroParquetWriter
	    	            .<GenericData.Record>builder(getOutputFile(path))
			            .withRowGroupSize(Integer.parseInt(System.getProperty("ROW-GROUP-SIZE", "1048576")))
			            .withPageSize(Integer.parseInt(System.getProperty("PAGE-SIZE", "1048576")))
	    	            .withSchema(parsedSchema)
	    	            .withConf(new Configuration())
	     	            .withCompressionCodec(CompressionCodecName.SNAPPY)
	    	            .withValidation(false)
	    	            .withDictionaryEncoding(false)
	    	            .build();
	}

	@Override
	public void write(List<String> record) throws IOException {
		GenericData.Record data = new GenericData.Record(parsedSchema);

		int iHeader = 0;
		for (String cell : record) {
			
			if (!cell.isEmpty()) {
				
				data.put(headers.get(iHeader), cell);
				
			}
			
			iHeader += 1;
		}
		
		writer.write(data);
		
	}	
	
}

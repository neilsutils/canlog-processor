package com.microsoft.j1939.Analyzer.IO;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLStreamHandler;
import java.security.InvalidKeyException;
import java.util.ArrayList;
import java.util.Date;

import org.apache.commons.lang3.StringUtils;
import org.apache.parquet.io.PositionOutputStream;

import com.microsoft.azure.storage.CloudStorageAccount;
import com.microsoft.azure.storage.StorageException;
import com.microsoft.azure.storage.blob.BlobOutputStream;
import com.microsoft.azure.storage.blob.BlockEntry;
import com.microsoft.azure.storage.blob.BlockListingFilter;
import com.microsoft.azure.storage.blob.CloudBlobClient;
import com.microsoft.azure.storage.blob.CloudBlobContainer;
import com.microsoft.azure.storage.blob.CloudBlockBlob;

public final class OutputParquetBlob {
	private static final int IO_BUF_SIZE = 16 * 1024;

	public static final String storageConnectionString = "DefaultEndpointsProtocol=https;"
			+ "AccountName=[ACCOUNT_NAME];" + "AccountKey=[ACCOUNT_KEY];" + "EndpointSuffix=core.windows.net";

	public static org.apache.parquet.io.OutputFile getOutputFile(URI uri) {

		return new org.apache.parquet.io.OutputFile() {
			@Override
			public PositionOutputStream create(long blockSizeHint) throws IOException {
				return makePositionOutputStream(uri, IO_BUF_SIZE, false);
			}

			@Override
			public PositionOutputStream createOrOverwrite(long blockSizeHint) throws IOException {
				return makePositionOutputStream(uri, IO_BUF_SIZE, true);
			}

			@Override
			public boolean supportsBlockSize() {
				return false;
			}

			@Override
			public long defaultBlockSize() {
				return 0;
			}

		};

	}

	private static PositionOutputStream makePositionOutputStream(URI uri, int ioBufSize, boolean trunc)
			throws IOException {
		try {
			URL.setURLStreamHandlerFactory(protocol -> "wasb".equals(protocol) ? new URLStreamHandler() {
			    protected URLConnection openConnection(URL url) throws IOException {
			        return new URLConnection(url) {
			            public void connect() throws IOException {
			                throw new IOException("Not Supported");
			            }
			        };
			    }
			} : null);
			
			URL url = uri.toURL();
			
			final CloudBlockBlob blob = (url.getProtocol().toLowerCase().equals("wasb")) ?  getBlobFromKey(uri) :
								getBlobFromToken(uri);
	
			final BlobOutputStream output = blob.openOutputStream();

			blob.setStreamWriteSizeInBytes(Integer.parseInt(System.getProperty("STREAM-WRITE-SIZE", "16384")));

			return new PositionOutputStream() {
				private long position = 0;
				private long flushMonitor = 0;
				private long flushCounter = 0;
				private final long flushFrequencySize = Long
						.parseLong(System.getProperty("FLUSH-FREQUECY-SIZE", "1000000"));

				@Override
				public void write(int b) throws IOException {
					output.write(b);
					position++;
					flush();
				}

				@Override
				public void write(byte[] b) throws IOException {

					output.write(b);
					position += b.length;
					flush();

				}

				@Override
				public void write(byte[] b, int off, int len) throws IOException {

					output.write(b, off, len);
					position += len;
					flush();

				}

				@Override
				public void flush() throws IOException {
					try {
						if (flushMonitor > flushFrequencySize) {
							System.out.println((new Date()).toString() + " - Flushed: '" + position + "' - written - '"
									+ flushMonitor + "'");
							output.flush();
							try {
								ArrayList<BlockEntry> blocks = blob.downloadBlockList(BlockListingFilter.UNCOMMITTED,
										null, null, null);

								System.out.println(
										(new Date()).toString() + " - Uncommitted: '" + blocks.size() + "' Blocks");

								flushMonitor = 0;
								flushCounter += 1;

							} catch (StorageException e) {

								e.printStackTrace();

								throw new IOException(e);

							}

						} else {
							flushMonitor = position - (flushCounter * flushFrequencySize);
						}

					} catch (IOException e) {
						e.printStackTrace();
					}

				}

				@Override
				public void close() throws IOException {
					System.out.println((new Date()).toString() + " - Closing Stream");
					output.close();
					System.out.println((new Date()).toString() + " - Stream Closed");

				}

				@Override
				public long getPos() throws IOException {
					return position;
				}

			};
		} catch (InvalidKeyException | URISyntaxException | StorageException e) {
			throw new IOException(e);
		}

	}
	
	private static CloudBlockBlob getBlobFromKey(URI uri) throws URISyntaxException, StorageException, InvalidKeyException {
		String connectionString = StringUtils.replace(storageConnectionString, "[ACCOUNT_NAME]", uri.getHost());
		connectionString = StringUtils.replace(connectionString, "[ACCOUNT_KEY]",
				StringUtils.substringAfter(uri.getQuery(), "key="));
		
		System.out.println("Connection Type: 'Key'");
		System.out.println("Connection String: '" + connectionString + "'");
		System.out.println("Container: '" + StringUtils.substringBefore(uri.getAuthority(), "@") + "'");
		System.out.println("Blob: '" + StringUtils.substringAfter(uri.getPath(), "/") + "'");

		CloudStorageAccount account = CloudStorageAccount.parse(connectionString);

		CloudBlobClient blobClient  = account.createCloudBlobClient();
		CloudBlobContainer container = blobClient
				.getContainerReference(StringUtils.substringBefore(uri.getAuthority(), "@"));
		container.createIfNotExists();

		return container.getBlockBlobReference(StringUtils.substringAfter(uri.getPath(), "/"));

	}
	
	private static CloudBlockBlob getBlobFromToken(URI uri) throws URISyntaxException, StorageException, InvalidKeyException {
		System.out.println("Connection Type: 'Token'");
		System.out.println("Connection String: '" + uri.toString() + "'");
		
		return new CloudBlockBlob(uri);

	}

}
/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package gadc;

import java.io.*;
import java.util.*;

import ghidra.app.util.bin.BinaryReader;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.ByteProviderInputStream;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.factory.GFileSystemFactoryFull;
import ghidra.formats.gfilesystem.factory.GFileSystemProbeFull;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * TODO: Provide class-level documentation that describes what this file system does.
 */
@FileSystemInfo(
		type = "fptlibfile", // ([a-z0-9]+ only)
		description = "Flash Partition Table",
		factory = gadcFPTFileSystem.MyFileSystemFactory.class)

public class gadcFPTFileSystem implements GFileSystem {

	private final FSRLRoot fsFSRL;
	private FileSystemIndexHelper<LibFileItem> fsih;
	private FileSystemRefManager refManager = new FileSystemRefManager(this);
	
	private ByteProvider provider;

	/**
	 * File system constructor.
	 * 
	 * @param fsFSRL The root {@link FSRL} of the file system.
	 * @param provider The file system provider.
	 */
	
	public gadcFPTFileSystem(FSRLRoot fsFSRL, ByteProvider provider) {
		this.fsFSRL = fsFSRL;
		this.provider = provider;
		this.fsih = new FileSystemIndexHelper<>(this, fsFSRL);
	}
	
	/**
	 * Mounts (opens) the file system.
	 * 
	 * @param monitor A cancellable task monitor.
	 * @throws IOException 
	 */

	public void mount(TaskMonitor monitor) throws IOException {
		monitor.setMessage("Opening " + gadcFPTFileSystem.class.getSimpleName() + "...");
		
		BinaryReader reader = new BinaryReader(provider, true);
		
		long startOffset = 0x30; // bypass 0x10 + header $FPT 0x20 
		
		while ((startOffset < reader.length()) && (reader.readByte(startOffset) != -1)) {
			if (monitor.isCancelled()) {
				break;
			}

			LibFileItem item = new LibFileItem();
			
			reader.setPointerIndex(startOffset);			
			String name = reader.readNextAsciiString(4);
			String owner = reader.readNextAsciiString(4);
			long offset = reader.readNextUnsignedInt();
			long size = reader.readNextUnsignedInt();

			item.name = name;
			item.owner = owner;
			item.offset = offset;
			item.size = size;
			item.end = offset + size;
			
			if (reader.readAsciiString(offset, 4).equals("$CPD")) {
				long entries = reader.readUnsignedInt(offset + 0x04);
				int header_version = reader.readUnsignedByte(offset + 0x08);
				int entry_version = reader.readUnsignedByte(offset + 0x09);
				int header_length = reader.readUnsignedByte(offset + 0x0A);
				int checksum = reader.readUnsignedByte(offset + 0x0B);

				item.entries = entries;
				item.header_version = header_version;
				item.entry_version = entry_version;
				item.header_length = header_length;
				item.checksum = checksum;
			}
							
			fsih.storeFile(item.name, fsih.getFileCount(), false, item.size, item);
			
			startOffset = startOffset + 0x20;
		}
		
		startOffset = reader.readUnsignedInt(startOffset - 0x18) + reader.readUnsignedInt(startOffset - 0x14);
		
		while (startOffset < reader.length()) {
			if (monitor.isCancelled()) {
				break;
			}
			
			reader.setPointerIndex(startOffset);
			
			if (reader.readNextAsciiString(4).equals("$CPD")) {
				LibFileItem item = new LibFileItem();
				
				long entries = reader.readNextUnsignedInt();
				int header_version = reader.readNextUnsignedByte();
				int entry_version = reader.readNextUnsignedByte();
				int header_length = reader.readNextUnsignedByte();
				int checksum = reader.readNextUnsignedByte();
				String partition_name = reader.readNextAsciiString(4);

				item.entries = entries;
				item.header_version = header_version;
				item.entry_version = entry_version;
				item.header_length = header_length;
				item.checksum = checksum;
				item.name = partition_name;
				
				item.offset = startOffset;
				long end = reader.length();
				while (reader.getPointerIndex() < reader.length()) {
					if (reader.readNextAsciiString(4).equals("$CPD")) {
						end = reader.getPointerIndex() - 0x04;
						break;
					}
				}
				item.end = end;
				item.size = end - startOffset;
				
				fsih.storeFile(item.name, fsih.getFileCount(), false, item.size, item);
			}
			startOffset = startOffset + 0x1000;
		}
	}

	@Override
	public void close() throws IOException {
		refManager.onClose();
		if (provider != null) {
			provider.close();
			provider = null;
		}
		fsih.clear();
	}

	@Override
	public String getName() {
		return fsFSRL.getContainer().getName();
	}

	@Override
	public FSRLRoot getFSRL() {
		return fsFSRL;
	}

	@Override
	public boolean isClosed() {
		return provider == null;
	}

	@Override
	public int getFileCount() {
		return fsih.getFileCount();
	}

	@Override
	public FileSystemRefManager getRefManager() {
		return refManager;
	}

	@Override
	public GFile lookup(String path) throws IOException {
		return fsih.lookup(path);
	}

	@Override
	public InputStream getInputStream(GFile file, TaskMonitor monitor)
			throws IOException, CancelledException {

		// TODO: Get an input stream for a file.  The following is an example of how the metadata
		// might be used to get an input stream from a stored provider offset.
	
		LibFileItem metadata = fsih.getMetadata(file);
		return (metadata != null)
				? new ByteProviderInputStream(provider, metadata.offset, metadata.size)
				: null;
	}

	@Override
	public List<GFile> getListing(GFile directory) throws IOException {
		return fsih.getListing(directory);
	}

	@Override
	public String getInfo(GFile file, TaskMonitor monitor) {

		LibFileItem metadata = fsih.getMetadata(file);
		return (metadata == null) ? null : FSUtilities.infoMapToString(getInfoMap(metadata));
	}

	public Map<String, String> getInfoMap(LibFileItem metadata) {
		Map<String, String> info = new LinkedHashMap<>();

		// TODO: Customize information about a file system entry.  The following is sample
		// information that might be useful.
		
		info.put("Partition name", metadata.name);
		info.put("Owner", metadata.owner);
		info.put("Offset", "0x" + Long.toHexString(metadata.offset));
		info.put("Size", "0x" + Long.toHexString(metadata.size));
		info.put("End", "0x" + Long.toHexString(metadata.end));
		info.put("Module count", Long.toUnsignedString(metadata.entries));
		info.put("Header version", Long.toUnsignedString(metadata.header_version));
		info.put("Entry version", Long.toUnsignedString(metadata.entry_version));
		info.put("Header size", "0x" + Long.toHexString(metadata.header_length));
		info.put("Checksum", "0x" + Long.toHexString(metadata.checksum));
				
		return info;
	}

	// TODO: Customize for the real file system.
	public static class MyFileSystemFactory
			implements GFileSystemFactoryFull<gadcFPTFileSystem>, GFileSystemProbeFull {

		@Override
		public gadcFPTFileSystem create(FSRL containerFSRL, FSRLRoot targetFSRL,
				ByteProvider byteProvider, File containerFile, FileSystemService fsService,
				TaskMonitor monitor) throws IOException, CancelledException {

			gadcFPTFileSystem fs = new gadcFPTFileSystem(targetFSRL, byteProvider);
			fs.mount(monitor);
			return fs;
		}
		
		@Override
		public boolean probe(FSRL containerFSRL, ByteProvider byteProvider, File containerFile,
				FileSystemService fsService, TaskMonitor monitor)
				throws IOException, CancelledException {

			// TODO: Quickly and efficiently examine the bytes in 'byteProvider' to determine if 
			// it's a valid file system.  If it is, return true. 

			byte[] tag = byteProvider.readBytes(0x10, 4);
			return Arrays.equals(tag, new byte[] {0x24, 0x46, 0x50, 0x54});
		}	
	}

	// TODO: Customize with metadata from files in the real file system.  This is just a stub.
	// The elements of the file system will most likely be modeled by Java classes external to this
	// file.
	private static class LibFileItem {
		private String name;
		private String owner;
		private long offset;
		private long size;
		private long end;
		private long entries;
		private int header_version;
		private int entry_version;
		private int header_length;
		private int checksum;
	}
}

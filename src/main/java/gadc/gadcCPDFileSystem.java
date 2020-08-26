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
		type = "cpdlibfile", // ([a-z0-9]+ only)
		description = "Code Partition",
		factory = gadcCPDFileSystem.MyFileSystemFactory.class)

public class gadcCPDFileSystem implements GFileSystem {

	public static GFileSystem fss;
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
	
	public gadcCPDFileSystem(FSRLRoot fsFSRL, ByteProvider provider) {
		this.fsFSRL = fsFSRL;
		this.provider = provider;
		this.fsih = new FileSystemIndexHelper<>(this, fsFSRL);
		this.fss = this;
	}
	
	/**
	 * Mounts (opens) the file system.
	 * 
	 * @param monitor A cancellable task monitor.
	 * @throws IOException 
	 */

	public void mount(TaskMonitor monitor) throws IOException {
		monitor.setMessage("Opening " + gadcCPDFileSystem.class.getSimpleName() + "...");
		
		BinaryReader reader = new BinaryReader(provider, true);
		
		long startOffset = 0x10; 
		
		while ((startOffset < reader.length()) && (reader.readUnsignedInt(startOffset) != 0x4)){
			if (monitor.isCancelled()) {
				break;
			}
			
			reader.setPointerIndex(startOffset);			
			String name = reader.readNextAsciiString(12);
			long bf_offset = reader.readNextUnsignedInt();
			long length = reader.readNextUnsignedInt();
			long reserved = reader.readNextUnsignedInt();
			
			LibFileItem item = new LibFileItem();
			item.name = name;
			item.reserved = reserved;
			//item.offset = bf_offset + 0x1000;
			item.offset = ((bf_offset >> 24 & 0x02) == 0x02) ? bf_offset & 0x00ffffff : bf_offset;
			
			item.size = length;

			fsih.storeFile(item.name, fsih.getFileCount(), false, item.size, item);
			
			startOffset = startOffset + 0x18;
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
		
		info.put("Name", metadata.name);
		info.put("Offset in partition", "0x" + Long.toHexString(metadata.offset));
		info.put("Size", "0x" + Long.toHexString(metadata.size));
		info.put("info", "0x" + Long.toHexString(metadata.reserved));		
		
		return info;
	}

	// TODO: Customize for the real file system.
	public static class MyFileSystemFactory
			implements GFileSystemFactoryFull<gadcCPDFileSystem>, GFileSystemProbeFull {

		@Override
		public gadcCPDFileSystem create(FSRL containerFSRL, FSRLRoot targetFSRL,
				ByteProvider byteProvider, File containerFile, FileSystemService fsService,
				TaskMonitor monitor) throws IOException, CancelledException {

			gadcCPDFileSystem fs = new gadcCPDFileSystem(targetFSRL, byteProvider);
			fs.mount(monitor);
			return fs;
		}
		
		@Override
		public boolean probe(FSRL containerFSRL, ByteProvider byteProvider, File containerFile,
				FileSystemService fsService, TaskMonitor monitor)
				throws IOException, CancelledException {

			// TODO: Quickly and efficiently examine the bytes in 'byteProvider' to determine if 
			// it's a valid file system.  If it is, return true. 

			byte[] tag = byteProvider.readBytes(0x0, 4);
			return Arrays.equals(tag, new byte[] {0x24, 0x43, 0x50, 0x44});
		}	
	}

	// TODO: Customize with metadata from files in the real file system.  This is just a stub.
	// The elements of the file system will most likely be modeled by Java classes external to this
	// file.
	private static class LibFileItem {
		private String name;
		private long reserved;
		private long offset;
		private long size;
	}
}
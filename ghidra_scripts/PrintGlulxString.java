//
//@author Nolan C.
//@category 
//@keybinding
//@menupath
//@toolbar

import java.io.IOException;
import java.io.InputStream;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import glulx.GlulxHeader;

public class PrintGlulxString extends GhidraScript {
	private static String decompressString(BinaryReader stringReader, BinaryReader tableReader) throws IOException {
		int type = stringReader.readNextUnsignedByte();
		if (type != 0xE1) {
			throw new IOException("0xE1 code not found.");
		}
		
		long rootAddr = tableReader.getPointerIndex();
		
		int n = 0;
		int b = 0;
		String str = "";
		
		boolean done = false;
		while (!done) {
			int nodeType = tableReader.readNextUnsignedByte();
			
			switch (nodeType) {
			case 0x00: // Branch (non-leaf node)
				long leftNode = tableReader.readNextUnsignedInt();
				long rightNode = tableReader.readNextUnsignedInt();
				
				if (n <= 0) {
					n = 8;
					b = stringReader.readNextUnsignedByte();
				}
				
				int bit = b & 1;
				b >>>= 1;
				n--;
				
				tableReader.setPointerIndex(bit != 0 ? rightNode : leftNode);
				break;
			case 0x01: // String terminator
				done = true;
				break;
			case 0x02: // Single character
				int ch = tableReader.readNextUnsignedByte();
				str += Character.toString(ch);
				tableReader.setPointerIndex(rootAddr);
				break;
			default:
				throw new IOException(String.format("Invalid string table node type 0x%02X", nodeType));
			}
		}
		
		return str;
	}
	
	@Override
	protected void run() throws Exception {		
		MemoryByteProvider provider = new MemoryByteProvider(currentProgram.getMemory(), currentProgram.getAddressFactory().getDefaultAddressSpace());
		BinaryReader reader = new BinaryReader(provider, false);
		BinaryReader tableReader = new BinaryReader(provider, false);
		
		GlulxHeader header = new GlulxHeader(reader);
		reader.setPointerIndex(currentAddress.getOffset());
		
		tableReader.setPointerIndex(header.getDecodingTable());
		tableReader.readNextUnsignedInt(); // Table Length (ignored)
		tableReader.readNextUnsignedInt(); // Number of Nodes (ignored)
		long rootAddr = tableReader.readNextUnsignedInt(); // Root Node Addr
		
		tableReader.setPointerIndex(rootAddr);
		
		try {
			String str = decompressString(reader, tableReader);
			println(str);
		} catch (IOException e) {
			printerr("Error: " + e.getMessage());
		}
	}
}

package glulx;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;

public class GlulxString {
	public static String decompressString(BinaryReader stringReader, BinaryReader tableReader) throws IOException {
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
}

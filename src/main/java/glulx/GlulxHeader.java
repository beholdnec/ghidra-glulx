package glulx;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class GlulxHeader implements StructConverter {
	public final static byte[] GLULX_MAGIC = "Glul".getBytes(StandardCharsets.US_ASCII);
	
	private byte[] magic;
	private byte[] version;
	private long ramstart;
	private long extstart;
	private long endmem;
	private long stackSize;
	private long startFunc;
	private long decodingTbl;
	private long checksum;
	
	public GlulxHeader(BinaryReader reader) throws IOException {
		magic = reader.readNextByteArray(4);
		
		if (!Arrays.equals(magic, GLULX_MAGIC)) {
			throw new IOException("Not a Glulx program.");
		}
		
		version = reader.readNextByteArray(4);
		ramstart = reader.readNextUnsignedInt();
		extstart = reader.readNextUnsignedInt();
		endmem = reader.readNextUnsignedInt();
		stackSize = reader.readNextUnsignedInt();
		startFunc = reader.readNextUnsignedInt();
		decodingTbl = reader.readNextUnsignedInt();
		checksum = reader.readNextUnsignedInt();
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType("header", 0);
		structure.add(STRING, 4, "magic", null);
		structure.add(DWORD, "version", null);
		structure.add(POINTER, "ramstart", null);
		structure.add(POINTER, "extstart", null);
		structure.add(POINTER, "endmem", null);
		structure.add(DWORD, "stacksize", null);
		structure.add(POINTER, "startfunc", null);
		structure.add(POINTER, "decodingTbl", null);
		structure.add(DWORD, "checksum", null);
		return structure;
	}
	
	public byte[] getMagic() {
		return magic;
	}
	
	public long getRamStart() {
		return ramstart;
	}
	
	public long getExtStart() {
		return extstart;
	}
	
	public long getStartFunc() {
		return startFunc;
	}
	
	public long getDecodingTable() {
		return decodingTbl;
	}
	
	public long getEndMem() {
		return endmem;
	}
}

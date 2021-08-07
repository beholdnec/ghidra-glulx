package glulx.data;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.docking.settings.Settings;
import ghidra.program.model.data.BuiltIn;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Dynamic;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.Memory;
import ghidra.util.Msg;
import glulx.GlulxHeader;
import glulx.GlulxString;

public class GlulxStringDataType extends BuiltIn implements Dynamic {
	public GlulxStringDataType() {
		this(null);
	}
	
	public GlulxStringDataType(DataTypeManager dtm) {
		super(null, "GlulxString", dtm);
	}

	@Override
	public DataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new GlulxStringDataType(dtm);
	}

	@Override
	public int getLength() {
		// String length is dynamic and dependent on memory contents.
		return -1;
	}

	@Override
	public String getDescription() {
		return "Glulx compressed string";
	}

	@Override
	public Object getValue(MemBuffer buf, Settings settings, int length) {
		// XXX: Return null here. Returning a string here causes Ghidra to display the text in a truncated format.
		// Returning null makes more text visible.
		return null;
//		try {
//			// FIXME: Is there any way to avoid parsing twice, once for getRepresentation and once for getLength?
//			Parsed parsed = parse(buf);
//			return parsed.string;
//		} catch (IOException e) {
//			return "PARSING ERROR: " + e.getMessage();
//		}
	}
	
	private static class Parsed {
		public String string;
		public long length;
	}
	
	private static Parsed parse(MemBuffer buf) throws IOException {
		Program program = buf.getMemory().getProgram();
		MemoryByteProvider provider = new MemoryByteProvider(program.getMemory(), program.getAddressFactory().getDefaultAddressSpace());
		BinaryReader reader = new BinaryReader(provider, false);
		BinaryReader tableReader = new BinaryReader(provider, false);
		
		GlulxHeader header = new GlulxHeader(reader);
		reader.setPointerIndex(buf.getAddress().getOffset());
		tableReader.setPointerIndex(header.getDecodingTable());
		tableReader.readNextUnsignedInt(); // Table Length (ignored)
		tableReader.readNextUnsignedInt(); // Number of Nodes (ignored)
		long rootAddr = tableReader.readNextUnsignedInt(); // Root Node Addr
		
		tableReader.setPointerIndex(rootAddr);
		
		Parsed result = new Parsed();
		result.string = GlulxString.decompressString(reader, tableReader);
		result.length = reader.getPointerIndex() - buf.getAddress().getOffset();
		return result;
	}

	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {
		try {
			// FIXME: Is there any way to avoid parsing twice, once for getRepresentation and once for getLength?
			Parsed parsed = parse(buf);
			return parsed.string;
		} catch (IOException e) {
			return "PARSING ERROR: " + e.getMessage();
		}
	}

	@Override
	public int getLength(MemBuffer buf, int maxLength) {
		try {
			// XXX: maxLength is ignored, as it is in PngDataType, et al.
			Parsed parsed = parse(buf);
			return (int)parsed.length;
		} catch (IOException e) {
			return 1;
		}
	}

	@Override
	public boolean canSpecifyLength() {
		return false;
	}

	@Override
	public DataType getReplacementBaseType() {
		return ByteDataType.dataType;
	}

}

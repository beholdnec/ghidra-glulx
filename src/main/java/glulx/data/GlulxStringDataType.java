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
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {
		// TODO
		Program program = buf.getMemory().getProgram();
		MemoryByteProvider provider = new MemoryByteProvider(program.getMemory(), program.getAddressFactory().getDefaultAddressSpace());
		BinaryReader reader = new BinaryReader(provider, false);
		BinaryReader tableReader = new BinaryReader(provider, false);
		
		try {
			GlulxHeader header = new GlulxHeader(reader);
			reader.setPointerIndex(buf.getAddress().getOffset());
			tableReader.setPointerIndex(header.getDecodingTable());
			tableReader.readNextUnsignedInt(); // Table Length (ignored)
			tableReader.readNextUnsignedInt(); // Number of Nodes (ignored)
			long rootAddr = tableReader.readNextUnsignedInt(); // Root Node Addr
			
			tableReader.setPointerIndex(rootAddr);
			
			return GlulxString.decompressString(reader, tableReader);
		} catch (IOException e) {
			Msg.error(this, e);
			return "PARSING ERROR: " + e.getMessage();
		}
	}

	@Override
	public int getLength(MemBuffer buf, int maxLength) {
		// TODO
		return 1;
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

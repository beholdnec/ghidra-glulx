package glulx.pcode;

import ghidra.app.plugin.processors.sleigh.PcodeEmit;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.lang.InjectPayload;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.Msg;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlParseException;
import ghidra.xml.XmlPullParser;

/** Pulls function parameters into local variables, similarly to JVM. */
public class InjectPayloadGlulxParameters implements InjectPayload {
	private String name;
	private String sourceName;
	private InjectParameter[] noParams;
	private boolean analysisStateRecoverable;
	private AddressSpace constantSpace;
	private int paramSpaceID;
	private int localSpaceID;
	private Varnode temp4;
	private Varnode zero;
	private Varnode four;
	private Varnode LVA;
	
	public InjectPayloadGlulxParameters(String nm, String srcName, SleighLanguage language, long uniqBase) {
		name = nm;
		sourceName = srcName;
		noParams = new InjectParameter[0];
		analysisStateRecoverable = true;
		constantSpace = language.getAddressFactory().getConstantSpace();
		
		AddressSpace uniqueSpace = language.getAddressFactory().getUniqueSpace();
		Address temp4Address = uniqueSpace.getAddress(uniqBase);
		
		AddressSpace paramSpace = language.getAddressFactory().getAddressSpace("param");
		paramSpaceID = paramSpace.getSpaceID();
		AddressSpace localSpace = language.getAddressFactory().getAddressSpace("local");
		localSpaceID = localSpace.getSpaceID();
		
		// create temp storage location
		temp4 = new Varnode(temp4Address, 4);
		
		// create varnodes for incrementing pointer by 4 bytes
		zero = new Varnode(constantSpace.getAddress(0), 4);
		four = new Varnode(constantSpace.getAddress(4), 4);
		
		Address LVAregAddress = language.getRegister("LVA").getAddress();
		LVA = new Varnode(LVAregAddress, 4);
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public int getType() {
		return CALLMECHANISM_TYPE;
	}

	@Override
	public String getSource() {
		return sourceName;
	}

	@Override
	public int getParamShift() {
		return 0;
	}

	@Override
	public InjectParameter[] getInput() {
		return noParams;
	}

	@Override
	public InjectParameter[] getOutput() {
		return noParams;
	}

	@Override
	public boolean isErrorPlaceholder() {
		return false;
	}

	@Override
	public void inject(InjectContext context, PcodeEmit emit) {
		// not used
	}

	@Override
	public PcodeOp[] getPcode(Program program, InjectContext con) {
		if (!analysisStateRecoverable) {
			return new PcodeOp[0];
		}
		
		Address funcAddr = con.baseAddr;
		// XXX: baseAddr points to the instruction following the C0/C1 function header,
		// not the function itself. Therefore we must use getFunctionContaining instead of
		// getFunctionAt. I have no idea why this happens.
		Function function = program.getFunctionManager().getFunctionContaining(funcAddr);
		if (function == null) {
			// Injection cannot be performed without a function.
			return new PcodeOp[0];
		}
		
		int numOps = function.getParameterCount();
		
		PcodeOp[] resOps = new PcodeOp[1 + 3 * numOps];
		int seqNum = 0;

		//initialize LVA to contain 0
		PcodeOp copy = new PcodeOp(con.baseAddr, seqNum, PcodeOp.COPY);
		copy.setInput(zero, 0);
		copy.setOutput(LVA);
		resOps[seqNum++] = copy;
		
		Varnode tempLocation = temp4;
		Varnode increment = four;
		
		// TODO: detect C0 or C1 function, fill all locals with 0's except those filled by params,
		//       pay attention to size (which will almost always be 4)
		for (int i = 0; i < numOps; i++) {
			//copy value from parameterSpace to temporary
			PcodeOp load = new PcodeOp(con.baseAddr, seqNum, PcodeOp.LOAD);
			load.setInput(new Varnode(constantSpace.getAddress(paramSpaceID), 4), 0);
			load.setInput(LVA, 1);
			load.setOutput(tempLocation);
			resOps[seqNum++] = load;
			//copy temporary to LVA
			PcodeOp store = new PcodeOp(con.baseAddr, seqNum, PcodeOp.STORE);
			store.setInput(new Varnode(constantSpace.getAddress(localSpaceID), 4), 0);
			store.setInput(LVA, 1);
			store.setInput(tempLocation, 2);
			resOps[seqNum++] = store;
			//increment LVA reg 
			PcodeOp add = new PcodeOp(con.baseAddr, seqNum, PcodeOp.INT_ADD);
			add.setInput(LVA, 0);
			add.setInput(increment, 1);
			add.setOutput(LVA);
			resOps[seqNum++] = add;
		}
		
		return resOps;
	}

	@Override
	public boolean isFallThru() {
		return true;
	}

	@Override
	public boolean isIncidentalCopy() {
		return false;
	}

	@Override
	public void saveXml(StringBuilder buffer) {
		// Provide a minimal tag so decompiler can call-back
		buffer.append("<pcode");
		SpecXmlUtils.encodeStringAttribute(buffer, "inject", "uponentry");
		SpecXmlUtils.encodeBooleanAttribute(buffer, "dynamic", true);
		buffer.append("/>\n");
	}

	@Override
	public void restoreXml(XmlPullParser parser, SleighLanguage language) throws XmlParseException {
		XmlElement el = parser.start();
		String injectString = el.getAttribute("inject");
		if (injectString == null || !injectString.equals("uponentry")) {
			throw new XmlParseException("Expecting inject=\"uponentry\" attribute");
		}
		boolean isDynamic = SpecXmlUtils.decodeBoolean(el.getAttribute("dynamic"));
		if (!isDynamic) {
			throw new XmlParseException("Expecting dynamic attribute");
		}
		parser.end(el);
	}

	/** All instances of InjectPayloadGlulxParameters are equal. This is required to prevent errors when opening Glulx files. */
	@Override
	public boolean equals(Object obj) {
		return (obj instanceof InjectPayloadGlulxParameters);		// All instances are equal
	}

	/** All instances of InjectPayloadGlulxParameters are equal. This is required to prevent errors when opening Glulx files. */
	@Override
	public int hashCode() {
		return 123474221;		// All instances are equal
	}
}

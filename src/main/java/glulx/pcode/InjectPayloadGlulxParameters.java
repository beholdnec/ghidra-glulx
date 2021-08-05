package glulx.pcode;

import ghidra.app.plugin.processors.sleigh.PcodeEmit;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.lang.InjectPayload;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
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
	private Varnode LVA;
	
	public InjectPayloadGlulxParameters(String nm, String srcName, SleighLanguage language, long uniqBase) {
		name = nm;
		sourceName = srcName;
		noParams = new InjectParameter[0];
		analysisStateRecoverable = true;
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
		
		// TODO
		return new PcodeOp[0];
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

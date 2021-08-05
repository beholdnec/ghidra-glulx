package glulx.pcode;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.lang.InjectPayload;
import ghidra.program.model.lang.PcodeInjectLibrary;

public class PcodeInjectLibraryGlulx extends PcodeInjectLibrary {
	public PcodeInjectLibraryGlulx(SleighLanguage l) {
		super(l);
	}
	
	@Override
	public InjectPayload allocateInject(String sourceName, String name, int tp) {
		if (tp == InjectPayload.CALLMECHANISM_TYPE) {
			return new InjectPayloadGlulxParameters(name, sourceName, language, tp);
		}
		return super.allocateInject(sourceName, name, tp);
	}
}

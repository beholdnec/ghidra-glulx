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
package glulx;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.*;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.QueryOpinionService;
import ghidra.app.util.opinion.QueryResult;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * TODO: Provide class-level documentation that describes what this loader does.
 */
public class GlulxLoader extends AbstractLibrarySupportLoader {

	@Override
	public String getName() {
		return "Glulx";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();
		
		BinaryReader reader = new BinaryReader(provider, false);
		GlulxHeader header = new GlulxHeader(reader);
		
		if (Arrays.equals(GlulxHeader.GLULX_MAGIC, header.getMagic())) {
			List<QueryResult> queries = QueryOpinionService.query(getName(), "1", null);
			for (QueryResult result : queries) {
				loadSpecs.add(new LoadSpec(this, 0, result));
			}
		}

		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {
		try {
			InputStream inputStream = provider.getInputStream(0);
			
			BinaryReader reader = new BinaryReader(provider, false);
			GlulxHeader header = new GlulxHeader(reader);
			
			Address memStart = program.getAddressFactory().getDefaultAddressSpace().getAddress(0);
			Address memEnd = program.getAddressFactory().getDefaultAddressSpace().getAddress(header.getEndMem());
			//program.getMemory().createInitializedBlock("mem", memStart, inputStream, header.getEndMem(), monitor, false);
			MemoryBlockUtils.createInitializedBlock(program, false, "mem", memStart, inputStream, header.getEndMem(), null, null, true, true, true, null, monitor);
			// TODO: set rom region to read-only
			// TODO: create uninitialized region
			
			DataUtilities.createData(program, memStart, header.toDataType(), -1, false, ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
			
			Register ramstartReg = program.getLanguage().getRegister("RAMSTART");
			program.getProgramContext().setValue(ramstartReg, memStart, memEnd, BigInteger.valueOf(header.getRamStart()));
			
			Address startAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(header.getStartFunc());
			program.getFunctionManager().createFunction("start", startAddr, new AddressSet(startAddr), SourceType.ANALYSIS);
		} catch (Exception e) {
			log.appendException(e);
		}
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram) {
		List<Option> list =
			super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);

		// TODO: If this loader has custom options, add them to 'list'
		list.add(new Option("Option name goes here", "Default option value goes here"));

		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {

		// TODO: If this loader has custom options, validate them here.  Not all options require
		// validation.

		return super.validateOptions(provider, loadSpec, options, program);
	}
}

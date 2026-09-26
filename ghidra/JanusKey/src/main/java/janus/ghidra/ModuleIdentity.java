package janus.ghidra;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import janus.trace.Row;

final class ModuleIdentity {
    static String problem(Program program,Row module) {
        if(!module.flag("pe_identity_valid"))return "Recorded module has no PE identity; use explicit runtime storage queries.";
        if(program.getLanguage().isBigEndian() || program.getDefaultPointerSize()!=8)return "Select the matching Windows x64 program.";
        try {
            Memory memory=program.getMemory();Address base=program.getImageBase();
            if(Short.toUnsignedInt(memory.getShort(base))!=0x5a4d)return "Program PE headers are unavailable at its image base.";
            long offset=Integer.toUnsignedLong(memory.getInt(base.add(0x3c)));
            if(offset>0x100000)return "Program PE header offset is invalid.";
            Address pe=base.addNoWrap(offset);
            if(memory.getInt(pe)!=0x4550)return "Program has no valid PE signature.";
            if(Short.toUnsignedInt(memory.getShort(pe.add(4)))!=module.number("machine"))return "PE machine differs from the recording.";
            if(Integer.toUnsignedLong(memory.getInt(pe.add(8)))!=module.number("pe_timestamp"))return "PE timestamp differs: this appears to be another build.";
            Address optional=pe.add(24);
            if(Short.toUnsignedInt(memory.getShort(optional))!=0x20b)return "Expected PE32+ optional header.";
            for(var field:new Object[][]{{"entry_point_rva",16},{"declared_image_size",56},{"pe_checksum",64}}) {
                if(Integer.toUnsignedLong(memory.getInt(optional.add((Integer)field[1])))!=module.number((String)field[0]))return "PE "+field[0]+" differs from the recording.";
            }
            return null;
        } catch(Exception e) {return "Cannot read program PE identity; use explicit runtime storage queries.";}
    }
}

package janus.ghidra;

import janus.trace.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.lang.Register;
import java.util.*;

record Inspection(Kind kind,String label,long address,int size,String register,int byteOffset,String note) {
    enum Kind { MEMORY, REGISTER, FUNCTION, INSTRUCTION, UNKNOWN }
    static Inspection memory(String label,long address,int size,String note) { return new Inspection(Kind.MEMORY,label,address,Math.max(1,Math.min(size,256)),"",0,note); }
    static Inspection unknown(String name,String note) { return new Inspection(Kind.UNKNOWN,name,0,0,"",0,note); }
    static Inspection storage(Program p,String label,Address a,int size,TraceProvider.Context c) {
        if(a==null) return unknown(label,"No concrete storage is available for this decompiler value.");
        if(a.isRegisterAddress()) {
            Register r=p.getRegister(a,size);
            if(r==null) return unknown(label,"Unrecognized register storage.");
            Register base=r.getBaseRegister(); int offset=r.getLeastSignificantBitInBaseRegister()/8;
            return new Inspection(Kind.REGISTER,label,0,Math.min(size,256),base.getName().toLowerCase(Locale.ROOT),offset,"Observed register storage; optimized variable lifetimes may be narrower.");
        }
        if(a.isMemoryAddress()) {
            Long runtime=c.runtime(a);
            return runtime==null?unknown(label,"Address is outside the selected module mapping."):memory(label,runtime,size,"Module-relative global storage.");
        }
        if(a.isStackAddress()) return new Inspection(Kind.MEMORY,label,a.getOffset(),Math.min(Math.max(size,1),256),"stack",0,"Stack storage resolved from the selected function's active call frame.");
        return unknown(label,"Optimized temporary: no unambiguous runtime storage. Inspect its instruction's recorded operands.");
    }
    static String escape(String text) { return text.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace("\"","&quot;"); }
}

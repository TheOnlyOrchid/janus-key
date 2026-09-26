package janus.trace;

import java.util.*;

public final class ValueEvidence {
    public final byte[] value;
    public final BitSet known;
    public final List<TraceStore.Event> sources;
    public final boolean beforeWrite;
    private ValueEvidence(byte[] value,BitSet known,List<TraceStore.Event> sources,boolean before) {
        this.value=value; this.known=known; this.sources=sources; beforeWrite=before;
    }
    public static ValueEvidence memory(long address,int size,List<TraceStore.Event> newestFirst) {
        byte[] value=new byte[size]; BitSet known=new BitSet(size), covered=new BitSet(size); List<TraceStore.Event> sources=new ArrayList<>(); boolean before=false;
        for(var e:newestFirst) {
            Row r=e.row(); byte[] bytes=r.bytes("value_hex"); long base=r.number("memory_address"), width=r.number("requested_size"); boolean used=false;
            for(int i=0;i<size;i++) {
                long delta=address+i-base;
                if(covered.get(i) || Long.compareUnsigned(delta,width)>=0) continue;
                covered.set(i); used=true;
                if(Long.compareUnsigned(delta,bytes.length)<0) { value[i]=bytes[(int)delta]; known.set(i); }
            }
            if(used) { sources.add(e); before|=r.text("access").equals("write_before"); }
            if(covered.cardinality()==size) break;
        }
        return new ValueEvidence(value,known,List.copyOf(sources),before);
    }
    public static ValueEvidence register(int offset,int size,List<TraceStore.Event> events) {
        byte[] value=new byte[size]; BitSet known=new BitSet(size);
        if(events.isEmpty()) return new ValueEvidence(value,known,List.of(),false);
        var e=events.get(0); byte[] b=e.row().bytes("value_hex");
        for(int i=0;i<size;i++) if(i+offset>=0 && i+offset<b.length) { value[i]=b[i+offset]; known.set(i); }
        return new ValueEvidence(value,known,List.of(e),e.row().text("access").equals("write_before"));
    }
    public String hex() { StringBuilder b=new StringBuilder(); for(int i=0;i<value.length;i++) { if(i>0)b.append(' '); b.append(known.get(i)?String.format("%02x",value[i]&255):"??"); } return b.toString(); }
    public String interpretation() {
        if(known.cardinality()!=value.length) return "Partial / unknown bytes";
        if(value.length>8) return "Bytes in memory order";
        byte[] big=new byte[value.length]; for(int i=0;i<value.length;i++) big[i]=value[value.length-i-1];
        return "unsigned "+new java.math.BigInteger(1,big)+"; signed "+new java.math.BigInteger(big);
    }
}

package janus.trace;

import java.util.*;

final class EventCache {
    private record Entry(List<TraceStore.Event> events,long bytes) {}
    private final LinkedHashMap<List<Object>,Entry> entries=new LinkedHashMap<>(64,.75f,true);
    private final long budget=16L*1024*1024;
    private long used;
    synchronized List<TraceStore.Event> get(List<Object> key){Entry entry=entries.get(key);return entry==null?null:copy(entry.events);}
    synchronized void put(List<Object> key,List<TraceStore.Event> value) {
        long bytes=64;for(var e:value){bytes+=estimate(e.row());if(e.instruction()!=null)bytes+=estimate(e.instruction());}
        if(bytes>budget)return;
        Entry previous=entries.put(List.copyOf(key),new Entry(copy(value),bytes));if(previous!=null)used-=previous.bytes;used+=bytes;
        var iterator=entries.entrySet().iterator();while(used>budget || entries.size()>256){var entry=iterator.next();used-=entry.getValue().bytes;iterator.remove();}
    }
    private static long estimate(Row row){long n=128;for(var entry:row.entrySet())n+=80L+2L*(entry.getKey().length()+entry.getValue().length());return n;}
    private static List<TraceStore.Event> copy(List<TraceStore.Event> source){List<TraceStore.Event> result=new ArrayList<>(source.size());for(var e:source)result.add(new TraceStore.Event(copy(e.row()),e.instruction()==null?null:copy(e.instruction())));return result;}
    private static Row copy(Row source){Row row=new Row(source.type);row.putAll(source);return row;}
}

package janus.trace;

import java.math.BigDecimal;
import java.nio.*;
import java.nio.charset.StandardCharsets;
import java.sql.*;
import java.util.*;
import java.util.function.*;

public final class TraceSearch {
    public enum Mode { VALUE, CHANGE, DETAILS }
    public enum Encoding { AUTO_TEXT, UTF8, UTF16_LE, HEX, UINT32_LE, UINT64_LE }
    public record Query(Mode mode,Encoding encoding,String find,String then,boolean matchCase,
            boolean writesOnly,String category,long thread,long start,long end,Long addressStart,
            Long addressEnd,String register,String function,String instruction,long maxGap,int limit) {
        public Query {
            Objects.requireNonNull(mode);Objects.requireNonNull(encoding);
            if(find.isEmpty() && mode!=Mode.DETAILS)throw new IllegalArgumentException("Enter a captured value to find.");
            if(mode==Mode.CHANGE && then.isEmpty())throw new IllegalArgumentException("Enter the later value as well.");
            if(start<0 || end<start || maxGap<0)throw new IllegalArgumentException("Invalid sequence range or maximum gap.");
            if(addressStart!=null && addressEnd!=null && Long.compareUnsigned(addressStart,addressEnd)>0)throw new IllegalArgumentException("Address range is reversed.");
            if(limit<1 || limit>10000)throw new IllegalArgumentException("Result limit must be 1 to 10000.");
        }
    }
    public record Hit(TraceStore.Event before,TraceStore.Event event,String storage,String evidence) {}
    public record Result(List<Hit> hits,long examined,boolean limited,boolean cancelled) {}
    private record Pattern(byte[] bytes,boolean[] wildcard,String label,boolean foldAscii) {
        boolean matches(byte[] data,int offset,BooleanSupplier cancelled) {
            if((offset&1023)==0){QueryControl.check();if(cancelled.getAsBoolean())throw new java.util.concurrent.CancellationException("Search cancelled");}
            for(int i=0;i<bytes.length;i++) {
                int a=Byte.toUnsignedInt(data[offset+i]), b=Byte.toUnsignedInt(bytes[i]);
                boolean asciiByte=!label.equals("UTF16_LE") || (i%2==0 && i+1<bytes.length && bytes[i+1]==0 && data[offset+i+1]==0);
                if(foldAscii && asciiByte){if(a>='A' && a<='Z')a+=32;if(b>='A' && b<='Z')b+=32;}
                if(!wildcard[i] && a!=b)return false;
            }
            return true;
        }
    }
    private static List<Pattern> patterns(String text,Encoding encoding,boolean matchCase) {
        if(encoding==Encoding.AUTO_TEXT){List<Pattern> p=new ArrayList<>(patterns(text,Encoding.UTF8,matchCase));p.addAll(patterns(text,Encoding.UTF16_LE,matchCase));return p;}
        byte[] bytes;boolean[] wildcard;
        if(encoding==Encoding.HEX) {
            String hex=text.replaceAll("\\s+","");
            if(hex.isEmpty() || hex.length()%2!=0 || !hex.matches("(?i)([0-9a-f]{2}|\\?\\?)+"))throw new IllegalArgumentException("Hex uses byte pairs: 68 65 ?? 6c 6f (?? matches one byte).");
            bytes=new byte[hex.length()/2];wildcard=new boolean[bytes.length];boolean any=false;
            for(int i=0;i<bytes.length;i++){String pair=hex.substring(i*2,i*2+2);wildcard[i]=pair.equals("??");if(!wildcard[i]){bytes[i]=(byte)Integer.parseInt(pair,16);any=true;}}
            if(!any)throw new IllegalArgumentException("Include at least one concrete byte.");
        } else {
            if(encoding==Encoding.UINT32_LE || encoding==Encoding.UINT64_LE) {
                long n=unsignedNumber(text);int size=encoding==Encoding.UINT32_LE?4:8;
                if(size==4 && Long.compareUnsigned(n,0xffffffffL)>0)throw new IllegalArgumentException("Value exceeds unsigned 32-bit range.");
                bytes=Arrays.copyOf(ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(n).array(),size);
            } else bytes=text.getBytes(encoding==Encoding.UTF16_LE?StandardCharsets.UTF_16LE:StandardCharsets.UTF_8);
            wildcard=new boolean[bytes.length];
        }
        if(bytes.length==0 || bytes.length>4096)throw new IllegalArgumentException("Search values must contain 1 to 4096 bytes.");
        return List.of(new Pattern(bytes,wildcard,encoding.name(),!matchCase && (encoding==Encoding.UTF8 || encoding==Encoding.UTF16_LE)));
    }
    public static long unsignedNumber(String text) {
        try {String s=text.trim();return s.startsWith("0x") || s.startsWith("0X")?Long.parseUnsignedLong(s.substring(2),16):Long.parseUnsignedLong(s);}
        catch(NumberFormatException e){throw new IllegalArgumentException("Expected an unsigned decimal number or 0x hexadecimal address: "+text);}
    }
    private static boolean contains(String haystack,String needle,boolean matchCase) {
        return matchCase?haystack.contains(needle):haystack.toLowerCase(Locale.ROOT).contains(needle.toLowerCase(Locale.ROOT));
    }
    public static void validate(Query q) {
        if(q.mode!=Mode.DETAILS)patterns(q.find,q.encoding,q.matchCase);
        if(q.mode==Mode.CHANGE)patterns(q.then,q.encoding,q.matchCase);
    }

    static List<int[]> candidateGrams(Query q) {
        if(q.mode==Mode.DETAILS || (!q.matchCase && (q.encoding==Encoding.AUTO_TEXT || q.encoding==Encoding.UTF8 || q.encoding==Encoding.UTF16_LE)))return null;
        List<Pattern> alternatives=new ArrayList<>(patterns(q.find,q.encoding,true));
        if(q.mode==Mode.CHANGE)alternatives.addAll(patterns(q.then,q.encoding,true));
        List<int[]> result=new ArrayList<>();
        for(Pattern pattern:alternatives){Set<Integer> grams=new LinkedHashSet<>();for(int i=0;i+2<pattern.bytes.length;i++)if(!pattern.wildcard[i] && !pattern.wildcard[i+1] && !pattern.wildcard[i+2]){grams.add(ValueIndex.gram(pattern.bytes,i));if(grams.size()==32)break;}if(grams.isEmpty())return null;result.add(grams.stream().mapToInt(Integer::intValue).toArray());}
        return result;
    }
    public static Result search(TraceStore store,Query q,BooleanSupplier cancelled,LongConsumer progress) throws Exception {
        return search(store,q,cancelled,progress,batch->{});
    }
    public static Result search(TraceStore store,Query q,BooleanSupplier cancelled,LongConsumer progress,Consumer<List<Hit>> batches) throws Exception {
        validate(q);
        List<Pattern> from=q.mode==Mode.DETAILS?List.of():patterns(q.find,q.encoding,q.matchCase);
        List<Pattern> to=q.mode==Mode.CHANGE?patterns(q.then,q.encoding,q.matchCase):List.of();
        List<Hit> hits=new ArrayList<>();long examined=0;
        Delivery delivery=new Delivery(hits,batches);
        try(PairHistory pairs=q.mode==Mode.CHANGE?new PairHistory():null;
            TraceStore.SearchCursor cursor=store.scanSearch(q)) {
            while(cursor.next(q,cancelled)) {
                TraceStore.SearchSample sample=cursor.sample;examined++;
                try {
                    if(q.mode==Mode.DETAILS) {
                        TraceStore.Event event=store.searchEvent(cursor.detailPayload);Row row=event.row();
                        if(contains(row.describe()+"\n"+event.routine()+"\n"+event.code(),q.find,q.matchCase))hits.add(new Hit(null,event,storage(store,sample,0),preview(row,q.encoding)));
                    } else {
                        byte[] data=sample.data();if(data==null)data=new byte[0];
                        TraceStore.Event event=null;
                        if(q.mode==Mode.CHANGE) {
                            for(int enc=0;enc<to.size();enc++) {
                                Pattern pattern=to.get(enc);
                                for(int offset=0;offset<=data.length-pattern.bytes.length;offset++)if(pattern.matches(data,offset,cancelled)) {
                                    if(!inAddressRange(sample,offset,q))continue;
                                    PairHistory.Key key=key(sample,offset,enc);Long before=pairs.get(key);
                                    if(before!=null) {
                                        long gap=sample.sequence()-before;
                                        if(gap>0 && (q.maxGap==0 || gap<=q.maxGap)) {
                                            if(event==null)event=store.searchEvent(sample.sequence());
                                            hits.add(new Hit(store.searchEvent(before),event,storage(store,sample,offset),"Earlier #"+before+" -> #"+event.sequence()+" | "+pattern.label+" | "+preview(event.row(),q.encoding)));
                                            pairs.remove(key);
                                        }else if(q.maxGap>0 && gap>q.maxGap)pairs.remove(key);
                                    }
                                    if(hits.size()>=q.limit)return new Result(List.copyOf(hits),examined,true,false);
                                }
                            }
                        }
                        boolean found=false;
                        for(int enc=0;enc<from.size();enc++) {
                            Pattern pattern=from.get(enc);
                            for(int offset=0;offset<=data.length-pattern.bytes.length;offset++)if(pattern.matches(data,offset,cancelled) && inAddressRange(sample,offset,q)) {
                                if(q.mode==Mode.CHANGE){pairs.put(key(sample,offset,enc),sample.sequence());}
                                else {event=store.searchEvent(sample.sequence());hits.add(new Hit(null,event,storage(store,sample,offset),pattern.label+" +"+offset+" | "+preview(event.row(),q.encoding)));found=true;break;}
                            }
                            if(found)break;
                        }
                    }
                    if(hits.size()>=q.limit)return new Result(List.copyOf(hits),examined,true,false);
                } finally {delivery.emit(false);if((examined&511)==0)progress.accept(examined);}
            }
            return new Result(List.copyOf(hits),examined,false,cancelled.getAsBoolean());
        } catch(java.util.concurrent.CancellationException | SQLException e) {
            if(!cancelled.getAsBoolean())throw e;
            return new Result(List.copyOf(hits),examined,false,true);
        } finally {delivery.emit(true);}
    }
    private static final class Delivery {
        final List<Hit> hits;final Consumer<List<Hit>> sink;int delivered;long last;
        Delivery(List<Hit> hits,Consumer<List<Hit>> sink){this.hits=hits;this.sink=sink;}
        void emit(boolean force){long now=System.nanoTime();if(hits.size()>delivered && (force || delivered==0 || hits.size()-delivered>=128 || now-last>=100_000_000L)){sink.accept(List.copyOf(hits.subList(delivered,hits.size())));delivered=hits.size();last=now;}}
    }
    private static boolean inAddressRange(TraceStore.SearchSample sample,int offset,Query q) {
        if(q.addressStart==null && q.addressEnd==null)return true;
        if(sample.type()!=5)return false;
        BigDecimal address=TraceStore.unsigned(sample.address()).add(BigDecimal.valueOf(offset));
        return (q.addressStart==null || address.compareTo(TraceStore.unsigned(q.addressStart))>=0) && (q.addressEnd==null || address.compareTo(TraceStore.unsigned(q.addressEnd))<=0);
    }
    private static PairHistory.Key key(TraceStore.SearchSample sample,int offset,int encoding) {
        return new PairHistory.Key(sample.type(),sample.type()==5?TraceStore.unsigned(sample.address()).add(BigDecimal.valueOf(offset)):BigDecimal.valueOf(sample.register()),sample.type()==5?-1:sample.thread(),sample.type()==5?0:offset,encoding);
    }
    private static String storage(TraceStore store,TraceStore.SearchSample sample,int offset) {
        return sample.type()==5?Row.hex(sample.address()+offset):sample.type()==6?store.registerName(sample.register())+" +"+offset+" (thread "+sample.thread()+")":"";
    }
    public static String preview(Row row,Encoding encoding) {
        byte[] data=row.bytes("value_hex");if(data.length==0)return "";
        byte[] shortData=Arrays.copyOf(data,Math.min(data.length,80));
        String utf8=new String(shortData,StandardCharsets.UTF_8),utf16=new String(Arrays.copyOf(shortData,shortData.length/2*2),StandardCharsets.UTF_16LE);
        String hex=HexFormat.ofDelimiter(" ").formatHex(shortData)+(data.length>80?" ...":"");
        return switch(encoding) {
            case HEX,UINT32_LE,UINT64_LE -> hex+" | UTF-8: "+printable(utf8)+" | UTF-16LE: "+printable(utf16);
            case UTF8 -> "UTF-8: "+printable(utf8)+" | "+hex;
            case UTF16_LE -> "UTF-16LE: "+printable(utf16)+" | "+hex;
            default -> "UTF-8: "+printable(utf8)+" | UTF-16LE: "+printable(utf16)+" | "+hex;
        };
    }
    private static String printable(String text) {return text.replace("\0","\\0").replace("\n","\\n").replace("\r","\\r").replace("\t","\\t").replaceAll("[\\p{Cntrl}]",".");}
}

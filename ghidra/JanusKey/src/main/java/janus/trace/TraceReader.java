package janus.trace;

import java.io.*;
import java.nio.*;
import java.nio.charset.*;
import java.nio.file.*;
import java.util.*;
import java.util.zip.CRC32;
import java.security.*;

public final class TraceReader {
    public interface Consumer { void accept(Row row) throws Exception; }
    public interface Progress { void update(long bytes) throws Exception; }
    public interface Decompressor { byte[] decode(byte[] stored, int size) throws IOException; }
    public record Result(long records, boolean incomplete) {}
    private static final int MAX_BLOCK = 64 * 1024 * 1024;

    private static final String[] SCHEMA = { "",
        "i:format_version q:unix_timestamp q:monotonic_ns i:pointer_size s:scope i:max_memory_bytes i:call_stack_bytes b:registers b:started",
        "q:sequence q:monotonic_ns i:module_id s:path a:base a:high a:load_offset a:entry_address a:mapped_size i:image_type b:pe_identity_valid i:machine i:pe_timestamp i:pe_checksum i:declared_image_size i:entry_point_rva b:is_main b:loaded",
        "q:instruction_id i:module_id a:address a:module_offset i:size x:encoding_hex s:routine s:disassembly",
        "q:sequence q:monotonic_ns i:thread_id q:instruction_id",
        "q:sequence q:monotonic_ns i:thread_id q:instruction_id a:memory_address i:operand_index i:element_index b:multi_element i:requested_size c:access x:value_hex",
        "q:sequence q:monotonic_ns i:thread_id q:instruction_id i:register_id c:access x:value_hex",
        "q:call_id q:sequence q:monotonic_ns i:thread_id q:instruction_id q:target_function_id a:target_address a:expected_return_address a:rcx a:rdx a:r8 a:r9 x:xmm0 x:xmm1 x:xmm2 x:xmm3 a:stack_pointer x:stack_snapshot i:depth b:direct",
        "q:sequence q:monotonic_ns i:thread_id q:instruction_id q:call_id a:target_address a:integer_return_low a:integer_return_high x:xmm0 x:xmm1 x:st0 i:depth b:matched",
        "q:sequence i:thread_id i:os_thread_id q:monotonic_ns b:started",
        "i:register_id s:name i:size",
        "q:sequence q:monotonic_ns i:thread_id q:instruction_id q:target_function_id a:target_address a:fall_through_address b:taken b:direct b:conditional",
        "q:syscall_id q:sequence q:monotonic_ns i:thread_id a:instruction_pointer a:number i:standard " + args(16) + "a:return_value b:entering",
        "q:sequence q:monotonic_ns i:thread_id i:reason i:info a:from_instruction_pointer a:to_instruction_pointer",
        "i:definition_id i:module_id a:address c:kind s:name",
        "q:operation_id q:sequence q:monotonic_ns i:thread_id i:definition_id c:action " + args(12) + "a:result a:base_address a:previous_address a:size a:protection b:succeeded b:entering b:matched",
        "q:function_id i:module_id a:address a:module_offset a:size s:name",
        "q:sequence q:monotonic_ns i:process_id i:parent_process_id i:related_process_id c:event b:follow_children_enabled b:followed d:exit_code s:output_directory s:command_line",
        "q:sequence q:monotonic_ns i:thread_id q:instruction_id a:address i:requested i:captured s:reason"
    };
    private record FieldSpec(char code,String name) {}
    private static final FieldSpec[][] FIELDS=Arrays.stream(SCHEMA).map(s->s.isEmpty()?new FieldSpec[0]:Arrays.stream(s.split(" ")).map(f->new FieldSpec(f.charAt(0),f.substring(2))).toArray(FieldSpec[]::new)).toArray(FieldSpec[][]::new);
    public static final String[] FILES = {"", "run", "modules", "instruction_definitions", "instruction_events",
        "memory_events", "register_events", "call_events", "return_events", "thread_events", "register_definitions",
        "branch_events", "syscall_events", "context_change_events", "memory_api_definitions", "memory_lifecycle_events",
        "function_definitions", "process_events", "capture_diagnostics"};
    private static String args(int n) { String s=""; for(int i=0;i<n;i++) s+="a:arg"+i+" "; return s; }
    private static ByteBuffer little(byte[] b) { return ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN); }
    private static void require(boolean ok, String message) throws IOException { if (!ok) throw new IOException(message); }

    public static Result read(Path source, Consumer sink, Progress progress, Decompressor codec) throws Exception {
        return read(source,sink,progress,codec,null);
    }
    public static Result read(Path source, Consumer sink, Progress progress, Decompressor codec, MessageDigest digest) throws Exception {
        if (Files.isDirectory(source) && !Files.exists(source.resolve("trace.jkt"))) return csv(source, sink, progress,digest);
        Path file = Files.isDirectory(source) ? source.resolve("trace.jkt") : source;
        try (InputStream in = new BufferedInputStream(digest==null?Files.newInputStream(file):new DigestInputStream(Files.newInputStream(file),digest))) {
            byte[] h=in.readNBytes(16);
            require(h.length==16 && Arrays.equals(Arrays.copyOf(h,8), new byte[]{74,75,69,89,84,82,67,0}), "Not a Janus Key trace");
            ByteBuffer header=little(h); header.position(8);
            require(header.getShort()==2 && header.get()==1, "Unsupported trace container");
            int pointer=Byte.toUnsignedInt(header.get()), preferred=Byte.toUnsignedInt(header.get());
            require((pointer==4 || pointer==8) && preferred<=1 && header.get()==1 && header.getShort()==0, "Unsupported container flags");
            long expected=1, count=0, position=16; boolean start=false;
            while (true) {
                progress.update(position); byte[] raw=in.readNBytes(32);
                if(raw.length==0) { require(start,"Missing run metadata"); return new Result(count,false); }
                if(raw.length<32) { require(start,"Missing run metadata"); return new Result(count,true); }
                ByteBuffer b=little(raw);
                require(b.getInt()==0x4b4c424a && b.getShort()==1,"Invalid block header");
                int kind=Byte.toUnsignedInt(b.get()); require(b.get()==0,"Unsupported block flags");
                long id=b.getLong(); int decoded=b.getInt(), stored=b.getInt(), records=b.getInt(), crc=b.getInt();
                require(id==expected && decoded>=0 && decoded<=MAX_BLOCK && stored>=0 && stored<=MAX_BLOCK && records>=0 && records<=decoded/5,"Invalid block bounds or ordering");
                byte[] payload=in.readNBytes(stored), footer=in.readNBytes(16);
                if(payload.length!=stored || footer.length!=16) { require(start,"Missing run metadata"); return new Result(count,true); }
                ByteBuffer f=little(footer);
                require(f.getInt()==0x4a424c4b && f.getInt()==stored+48 && f.getLong()==id,"Invalid committed block footer");
                require(kind<=1,"Unsupported block codec");
                byte[] data=kind==0 ? payload : codec.decode(payload,decoded);
                require(data.length==decoded,"Incorrect decoded block size");
                CRC32 check=new CRC32(); check.update(data); require((int)check.getValue()==crc,"Block checksum mismatch");

                ByteBuffer scan=little(data); int seen=0;
                while(scan.hasRemaining()) { require(scan.remaining()>=5,"Truncated record envelope"); scan.get(); int n=scan.getInt(); require(n>=0 && n<=scan.remaining(),"Invalid record size"); scan.position(scan.position()+n); seen++; }
                require(seen==records,"Block record count mismatch");
                scan.rewind();
                while(scan.hasRemaining()) {
                    QueryControl.check();
                    int type=Byte.toUnsignedInt(scan.get()), size=scan.getInt(); ByteBuffer record=scan.slice().order(ByteOrder.LITTLE_ENDIAN); record.limit(size); scan.position(scan.position()+size);
                    require(type>0 && type<SCHEMA.length,"Unsupported record type "+type+"; update Janus Key to read this capture without discarding evidence");
                    if(type>0 && type<SCHEMA.length) {
                        Row row=parse(type,record); if(type==1) { require(row.number("format_version")==20,"Unsupported trace format (requires version 20)"); require(row.number("pointer_size")==pointer,"Inconsistent pointer size"); start|=row.flag("started"); }
                        sink.accept(row); count++;
                    }
                }
                expected++; position+=stored+48L;
            }
        }
    }
    private static Row parse(int type, ByteBuffer b) throws IOException {
        Row r=new Row(type);
        try {
            for(FieldSpec field:FIELDS[type]) {
                char code=field.code(); String name=field.name(), value;
                value=switch(code) {
                    case 'q' -> Long.toUnsignedString(b.getLong());
                    case 'a' -> Row.hex(b.getLong());
                    case 'i' -> Long.toString(Integer.toUnsignedLong(b.getInt()));
                    case 'd' -> Integer.toString(b.getInt());
                    case 'c' -> Integer.toString(Byte.toUnsignedInt(b.get()));
                    case 'b' -> { int flag=Byte.toUnsignedInt(b.get()); require(flag<=1,"Invalid boolean"); yield Boolean.toString(flag!=0); }
                    case 's', 'x' -> { int n=b.getInt(); require(n>=0 && n<=b.remaining(),"Invalid field size"); byte[] v=new byte[n]; b.get(v); yield code=='x' ? HexFormat.of().formatHex(v) : StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(v)).toString(); }
                    default -> throw new IOException("Unknown schema field");
                };
                r.put(name,value);
            }
            require(!b.hasRemaining(),"Unexpected fields in v20 record"); normalize(r,true); return r;
        } catch(BufferUnderflowException | IllegalArgumentException e) { throw new IOException("Malformed record type "+type,e); }
    }
    private static void normalize(Row r, boolean binary) throws IOException {
        if(binary) {
            if(r.containsKey("started")) r.put("event",r.flag("started")?"start":"finish");
            if(r.containsKey("loaded")) r.put("event",r.flag("loaded")?"load":"unload");
            if(r.containsKey("entering")) r.put("event",r.flag("entering")?"enter":"exit");
            if(r.type==5 || r.type==6) r.put("access",enumValue(r.number("access"),r.type==5?new String[]{"read","write_before","write_after","prefetch"}:new String[]{"read_before","write_before","write_after"}));
            if(r.type==15) r.put("action",enumValue(r.number("action"),new String[]{"allocate","reallocate","free","protect","map","unmap"}));
            if(r.type==17) r.put("event",enumValue(r.number("event"),new String[]{"start","child","finish"}));
        } else {
            if(r.type==1 || r.type==9) r.put("started",Boolean.toString(r.text("event").equals("start")));
            if(r.type==2) r.put("loaded",Boolean.toString(r.text("event").equals("load")));
        }
        if(r.type==5) r.put("copied_size",Integer.toString(r.text("value_hex").length()/2));
    }
    private static String enumValue(long n,String[] values) throws IOException { require(n>=0 && n<values.length,"Invalid enumeration"); return values[(int)n]; }
    private static Result csv(Path dir, Consumer sink, Progress progress, MessageDigest digest) throws Exception {
        require(Files.isRegularFile(dir.resolve("run.csv")),"Select a trace.jkt file or a CSV run directory");
        long count=0; boolean start=false;
        for(int type=1;type<FILES.length;type++) {
            Path file=dir.resolve(FILES[type]+".csv");
            if(type==18 && !Files.exists(file)) continue;
            require(Files.isRegularFile(file),"Missing dataset: "+file.getFileName());
            try(PushbackReader reader=new PushbackReader(new BufferedReader(new InputStreamReader(digest==null?Files.newInputStream(file):new DigestInputStream(Files.newInputStream(file),digest),StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT))),1)) {
                List<String> keys=csvRow(reader); require(keys!=null,"Missing CSV header");
                require(new HashSet<>(keys).size()==keys.size(),"Duplicate CSV columns");
                for(FieldSpec field:FIELDS[type]) {
                    String name=field.name();
                    if(Set.of("started","loaded","entering").contains(name)) name="event";
                    require(keys.contains(name),"Missing CSV column: "+name);
                }
                List<String> values;
                while((values=csvRow(reader))!=null) {
                    require(values.size()==keys.size(),"CSV row width mismatch in "+file.getFileName());
                    Row row=new Row(type); for(int i=0;i<keys.size();i++) row.put(keys.get(i),values.get(i));
                    validateCsv(row);
                    normalize(row,false);
                    if(type==1) { require(row.number("format_version")==20,"Unsupported trace format (requires version 20)"); start|=row.flag("started"); }
                    sink.accept(row); if((++count&4095)==0) progress.update(count);
                }
            }
        }
        require(start,"Missing run start"); return new Result(count,false);
    }
    private static void validateCsv(Row row) throws IOException {
        try {
            for(FieldSpec field:FIELDS[row.type]) {
                char type=field.code();String name=field.name(), value=row.text(name);
                if(Set.of("started","loaded","entering").contains(name)) {
                    String event=row.text("event");Set<String> allowed=name.equals("loaded")?Set.of("load","unload"):name.equals("entering")?Set.of("enter","exit"):Set.of("start","finish");
                    require(allowed.contains(event),"Invalid CSV event");continue;
                }
                if(type=='c' && name.equals("access")) {require((row.type==5?Set.of("read","write_before","write_after","prefetch"):Set.of("read_before","write_before","write_after")).contains(value),"Invalid CSV access");continue;}
                if(type=='c' && name.equals("action")) {require(Set.of("allocate","reallocate","free","protect","map","unmap").contains(value),"Invalid CSV action");continue;}
                if(type=='c' && row.type==17) {require(Set.of("start","child","finish").contains(value),"Invalid CSV process event");continue;}
                switch(type) {
                    case 'a' -> {require(value.matches("0x[0-9a-fA-F]{1,16}") || (row.type==16 && name.equals("size") && value.matches("[0-9]+")),"Invalid CSV address: "+name);row.put(name,Row.hex(row.number(name)));}
                    case 'q', 'i', 'c' -> {require(value.matches("[0-9]+"),"Invalid CSV integer: "+name);long n=Long.parseUnsignedLong(value);require(type=='q' || Long.compareUnsigned(n,type=='i'?0xffffffffL:255)<=0,"CSV integer out of range");row.put(name,Long.toUnsignedString(n));}
                    case 'd' -> Integer.parseInt(value);
                    case 'b' -> require(Set.of("true","false").contains(value),"Invalid CSV boolean: "+name);
                    case 'x' -> {HexFormat.of().parseHex(value);row.put(name,value.toLowerCase(Locale.ROOT));}
                    default -> { }
                }
            }
        } catch(IllegalArgumentException e) {throw new IOException("Malformed CSV record in "+FILES[row.type],e);}
    }

    static List<String> csvRow(PushbackReader in) throws IOException {
        List<String> row=new ArrayList<>(); StringBuilder s=new StringBuilder(); boolean quoted=false, closed=false, any=false;
        while(true) {
            int c=in.read();
            if(c<0) { require(!quoted,"Unterminated CSV quote"); if(!any) return null; row.add(s.toString()); return row; }
            any=true;
            if(quoted) {
                if(c=='"') { int n=in.read(); if(n=='"') s.append('"'); else { quoted=false; closed=true; if(n>=0) in.unread(n); } }
                else s.append((char)c);
            } else if(c==',' || c=='\n' || c=='\r') {
                row.add(s.toString()); s.setLength(0); closed=false;
                if(c!=',') { if(c=='\r') { int n=in.read(); if(n>=0 && n!='\n') in.unread(n); } return row; }
            } else if(c=='"' && s.isEmpty() && !closed) quoted=true;
            else { require(!closed && c!='"',"Invalid CSV quoting"); s.append((char)c); }
            require(s.length()<=MAX_BLOCK && row.size()<256,"CSV field or row too large");
        }
    }
}

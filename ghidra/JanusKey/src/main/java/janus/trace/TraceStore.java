package janus.trace;

import java.io.*;
import java.math.BigDecimal;
import java.nio.file.*;
import java.sql.*;
import java.util.*;

public final class TraceStore implements AutoCloseable {
    public final Path source;
    public final String label;
    public long count, firstSequence, lastSequence, captureDiagnostics, missingSequences;
    private final Map<String,Long> timelineCounts=new HashMap<>();
    private final long[] categoryTotals=new long[7];
    private final Map<Long,long[]> threadTotals=new HashMap<>();
    private static final String[] CATEGORIES={"All events","Writes","Calls / returns","Control flow","Memory lifetime","System / process","Capture diagnostics"};
    public boolean incomplete, finished;
    private final Path directory;
    private final TraceCache.Lease cache;
    private final TimelineIndex timelineIndex;
    private final EventCache eventCache;
    private boolean loaded;
    public boolean reused;
    private final Connection db;
    private final TraceStore owner;
    private int searchLeases;
    private boolean closed;
    private final Map<Long,Row> instructionCache=new LinkedHashMap<>(8192,.75f,true) {
        @Override protected boolean removeEldestEntry(Map.Entry<Long,Row> entry){return size()>8192;}
    };
    private PreparedStatement insert;
    private PreparedStatement instructionInsert;
    private int pending;
    private final Map<Long,String> registerNames=new HashMap<>();
    private final Set<Long> recordedThreads=new TreeSet<>();
    private long maxMemoryWidth,capturedSamples;
    public record Event(Row row, Row instruction) {
        public long sequence() { return row.number("sequence"); }
        public String code() { return instruction==null ? "" : instruction.text("disassembly"); }
        public String routine() { return instruction==null ? "" : instruction.text("routine"); }
    }
    private static final class InvalidCacheException extends IOException {InvalidCacheException(String message,Throwable cause){super(message,cause);}}
    public static TraceStore openPrepared(Path source,LoadProgress progress) throws Exception {
        for(int attempt=0;;attempt++) {
            TraceStore store=null;
            try {store=new TraceStore(source);store.loadDetailed(progress);return store;}
            catch(Exception e){if(store!=null)try{store.close();}catch(Exception close){e.addSuppressed(close);}if(!(e instanceof InvalidCacheException) || attempt!=0)throw e;progress.update("Rebuilding invalid prepared data",0,-1);}
        }
    }
    public TraceStore(Path selected) throws Exception {
        owner=null;eventCache=new EventCache();
        Path source=selected.toAbsolutePath().normalize();if(Files.isDirectory(source) && Files.isRegularFile(source.resolve("trace.jkt")))source=source.resolve("trace.jkt");
        this.source=source;
        this.label=Files.isDirectory(source)?source.getFileName().toString():source.getParent().getFileName().toString();
        Class.forName("org.h2.Driver");
        cache=TraceCache.acquire(this.source);directory=cache.directory;timelineIndex=new TimelineIndex(directory);
        Connection opened=null;boolean prepared=cache.ready;
        try {
            db=opened=connect(directory);

            try(Statement setup=db.createStatement()){setup.execute("SET LAZY_QUERY_EXECUTION TRUE");}
            if(!prepared)try(Statement s=statement()) {
                s.execute("CREATE TABLE evidence (id BIGINT GENERATED ALWAYS AS IDENTITY, kind INT, seq BIGINT, tid BIGINT, iid BIGINT, mid BIGINT, off BIGINT, addr NUMERIC(20), endaddr NUMERIC(21), reg BIGINT, access VARCHAR, cid BIGINT, target NUMERIC(20), payload VARBINARY, captured VARBINARY)");
                s.execute("CREATE TABLE instructions (iid BIGINT PRIMARY KEY, mid BIGINT, off BIGINT, payload VARBINARY, routine VARCHAR, disassembly VARCHAR, routine_fold VARCHAR, disassembly_fold VARCHAR)");
            }
            db.setAutoCommit(false);
            if(!prepared) {
                insert=prepare("INSERT INTO evidence(kind,seq,tid,iid,mid,off,addr,endaddr,reg,access,cid,target,payload,captured) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)");
                instructionInsert=prepare("INSERT INTO instructions VALUES(?,?,?,?,?,?,?,?)");
            }
        }catch(Exception e){boolean busy=databaseBusy(e);if(opened!=null)try{opened.close();}catch(Exception close){e.addSuppressed(close);}if(prepared && !busy)try{cache.discard();}catch(Exception cleanup){e.addSuppressed(cleanup);}try{cache.release();}catch(Exception cleanup){e.addSuppressed(cleanup);}if(prepared && !busy)throw new InvalidCacheException("Could not open prepared data",e);throw e;}
    }
    private static boolean databaseBusy(Throwable failure){for(Throwable cause=failure;cause!=null;cause=cause.getCause())if(cause instanceof SQLException sql && sql.getErrorCode()==90020)return true;return false;}
    private static Connection connect(Path directory) throws SQLException {return DriverManager.getConnection("jdbc:h2:file:"+directory.resolve("trace").toString().replace('\\','/')+";CACHE_SIZE=32768;DB_CLOSE_ON_EXIT=FALSE","sa","");}
    private PreparedStatement prepare(String sql,int... options) throws SQLException {return QueryControl.track(options.length==0?db.prepareStatement(sql):db.prepareStatement(sql,options[0],options[1]));}
    private Statement statement() throws SQLException {return QueryControl.track(db.createStatement());}
    public Path cacheDirectory(){return directory;}
    public static Path cacheRoot(){return TraceCache.root();}
    public static void pruneCache() throws IOException {TraceCache.prune();}
    public static void clearUnusedCache() throws IOException {TraceCache.clearUnused();}
    public static long cacheBytes() throws IOException {return TraceCache.cacheBytes();}
    public static long cacheQuotaBytes(){return TraceCache.quotaBytes();}
    public void discardCache() throws IOException {cache.discard();}
    public void load(TraceReader.Progress progress) throws Exception {
        loadDetailed((phase,completed,total)->progress.update(completed));
    }
    public interface LoadProgress {void update(String phase,long completed,long total) throws Exception;}
    public void loadDetailed(LoadProgress progress) throws Exception {
        if(loaded)return;
        if(cache.ready) {
            progress.update("Opening prepared recording",0,1);
            try {restoreMetadata(cache.metadata);}
            catch(Exception e){QueryControl.check();cache.discard();throw new InvalidCacheException("Prepared data is incomplete",e);}
            ensureCoverageSummary(progress);
            prepareValueIndex(progress);loaded=true;reused=true;progress.update("Prepared recording ready",1,1);return;
        }
        Path binary=Files.isDirectory(source)?source.resolve("trace.jkt"):source;
        boolean isBinary=Files.isRegularFile(binary);long bytes=isBinary?Files.size(binary):-1;
        try(WindowsXpress codec=new WindowsXpress()) {
            progress.update("Reading recording",0,bytes);
            java.security.MessageDigest digest=java.security.MessageDigest.getInstance("SHA-256");
            TraceReader.Result result=TraceReader.read(source,this::accept,n->progress.update(isBinary?"Reading recording":"Reading CSV: "+n+" records",n,bytes),codec,digest);
            count=result.records(); incomplete=result.incomplete(); flush(); insert.close(); insert=null;instructionInsert.close();instructionInsert=null;
            progress.update("Building indexes",0,10);
            try(Statement s=statement()) {
                int complete=0;
                for(String columns:List.of("seq", "kind,seq", "tid,seq", "iid,seq", "kind,addr,seq", "kind,reg,tid,seq", "kind,cid", "kind,target,seq")) {
                    progress.update("Building index "+columns,complete++,10); s.execute("CREATE INDEX idx_"+columns.replace(',','_')+" ON evidence("+columns+")");
                }
                progress.update("Indexing instruction addresses",8,10);
                s.execute("CREATE INDEX instruction_offset ON instructions(mid,off)");
                progress.update("Preparing execution counts",9,10);
                s.execute("CREATE TABLE execution_counts AS SELECT iid,tid,COUNT(*) executions FROM evidence WHERE kind=4 GROUP BY iid,tid");
                s.execute("CREATE INDEX execution_iid ON execution_counts(iid,tid)");
                progress.update("Preparing call lifetimes",9,10);
                s.execute("CREATE TABLE call_returns AS SELECT cid,tid,MIN(seq) returned FROM evidence WHERE kind=8 GROUP BY cid,tid");
                s.execute("CREATE UNIQUE INDEX return_call_thread ON call_returns(cid,tid)");
                s.execute("CREATE TABLE call_lifetimes AS SELECT c.seq,c.tid,c.cid,c.target,r.returned FROM evidence c LEFT JOIN call_returns r ON r.cid=c.cid AND r.tid=c.tid WHERE c.kind=7");
                s.execute("DROP TABLE call_returns");
                s.execute("CREATE INDEX call_thread_seq ON call_lifetimes(tid,seq)");
            }
            ensureCoverageSummary(progress);
            timelineIndex.build(db,progress,categoryTotals[0]);
            prepareValueIndex(progress);
            missingSequences=Math.max(0,lastSequence-categoryTotals[0]);
            db.commit();
            for(int i=0;i<CATEGORIES.length;i++){timelineCounts.put("-1:"+CATEGORIES[i],categoryTotals[i]);for(var entry:threadTotals.entrySet())timelineCounts.put(entry.getKey()+":"+CATEGORIES[i],entry.getValue()[i]);}
            try(Statement s=statement()){s.execute("CHECKPOINT SYNC");}
            Properties metadata=metadata();metadata.setProperty("sha256",HexFormat.of().formatHex(digest.digest()));cache.publish(source,metadata);loaded=true;
            progress.update("Indexed "+count+" records",10,10);
        }
    }
    private void prepareValueIndex(LoadProgress progress) throws Exception {
        try {new ValueIndex(directory).ensure(db,progress,capturedSamples);}
        catch(IOException | SQLException e){QueryControl.check();progress.update("Value-search summaries unavailable; complete search remains available",0,-1);}
    }
    private void ensureCoverageSummary(LoadProgress progress) throws Exception {

        synchronized(cache) { ensureCoverageSummaryLocked(progress); }
    }
    private void ensureCoverageSummaryLocked(LoadProgress progress) throws Exception {
        Path marker=directory.resolve("coverage.v1.ready");
        if(Files.isRegularFile(marker)) {
            try(Statement s=statement();ResultSet r=s.executeQuery("SELECT mid FROM coverage_modules FETCH FIRST 1 ROW ONLY")){return;}
            catch(SQLException invalid){QueryControl.check();Files.deleteIfExists(marker);}
        }
        QueryControl.check();progress.update("Preparing coverage summaries",0,2);Path staged=Files.createTempFile(directory,"coverage-",".pending");
        try {
            try(Statement s=statement()) {
                s.execute("DROP TABLE IF EXISTS coverage_modules");
                s.execute("DROP TABLE IF EXISTS coverage_counts");
                s.execute("CREATE TABLE coverage_modules AS SELECT i.mid,i.iid,SUM(e.executions) executions FROM instructions i JOIN execution_counts e ON e.iid=i.iid GROUP BY i.mid,i.iid");
                s.execute("CREATE INDEX coverage_module ON coverage_modules(mid,executions DESC,iid)");
            }
            db.commit();
            try(Statement s=statement()){s.execute("CHECKPOINT SYNC");}
            progress.update("Preparing coverage summaries",1,2);
            QueryControl.check();Files.write(staged,new byte[]{99,111,118,101,114,97,103,101,45,118,49,10});
            try {Files.move(staged,marker,StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);}catch(AtomicMoveNotSupportedException e){Files.move(staged,marker,StandardCopyOption.REPLACE_EXISTING);}
            progress.update("Preparing coverage summaries",2,2);
        } finally {Files.deleteIfExists(staged);}
    }
    private Properties metadata() {
        Properties p=new Properties();p.setProperty("capturedSamples",Long.toString(capturedSamples));p.setProperty("count",Long.toString(count));p.setProperty("first",Long.toString(firstSequence));p.setProperty("last",Long.toString(lastSequence));p.setProperty("diagnostics",Long.toString(captureDiagnostics));p.setProperty("missing",Long.toString(missingSequences));p.setProperty("maxWidth",Long.toString(maxMemoryWidth));p.setProperty("finished",Boolean.toString(finished));p.setProperty("incomplete",Boolean.toString(incomplete));
        registerNames.forEach((k,v)->p.setProperty("register."+k,v));for(long t:recordedThreads)p.setProperty("thread."+t,"true");timelineCounts.forEach((k,v)->p.setProperty("total."+k,Long.toString(v)));return p;
    }
    private void restoreMetadata(Properties p) throws Exception {
        capturedSamples=Long.parseLong(p.getProperty("capturedSamples","-1"));count=Long.parseLong(p.getProperty("count"));firstSequence=Long.parseLong(p.getProperty("first"));lastSequence=Long.parseLong(p.getProperty("last"));captureDiagnostics=Long.parseLong(p.getProperty("diagnostics"));missingSequences=Long.parseLong(p.getProperty("missing"));maxMemoryWidth=Long.parseLong(p.getProperty("maxWidth"));finished=Boolean.parseBoolean(p.getProperty("finished"));incomplete=Boolean.parseBoolean(p.getProperty("incomplete"));
        for(String key:p.stringPropertyNames())if(key.startsWith("register."))registerNames.put(Long.parseLong(key.substring(9)),p.getProperty(key));else if(key.startsWith("thread."))recordedThreads.add(Long.parseLong(key.substring(7)));else if(key.startsWith("total."))timelineCounts.put(key.substring(6),Long.parseLong(p.getProperty(key)));
        for(var total:timelineCounts.entrySet()){int colon=total.getKey().indexOf(':');if(timelineIndex.count(Long.parseLong(total.getKey().substring(0,colon)),total.getKey().substring(colon+1))!=total.getValue())throw new IOException("Incomplete timeline postings");}
        try(Statement s=statement();ResultSet r=s.executeQuery("SELECT iid FROM execution_counts FETCH FIRST 1 ROW ONLY")){}
    }
    private void accept(Row row) throws Exception {
        QueryControl.check();
        long seq=row.number("sequence");
        if(seq<0 || (row.containsKey("sequence") && seq==0)) throw new IOException("Invalid event sequence");
        if(row.type==18) captureDiagnostics++;
        if((row.type==5 || row.type==6) && !row.text("access").equals("prefetch"))capturedSamples++;
        if(row.type==1) finished|=row.text("event").equals("finish");
        if(row.type==10)registerNames.put(row.number("register_id"),row.text("name"));
        if(row.type==4 || row.type==5 || row.type==6 || row.type==7 || row.type==8 || row.type==9 || row.type==11 || row.type==12 || row.type==13 || row.type==15)recordedThreads.add(row.number("thread_id"));
        if(row.type==5)maxMemoryWidth=Math.max(maxMemoryWidth,row.number("requested_size"));
        lastSequence=Math.max(lastSequence,seq);
        if(seq>0 && (firstSequence==0 || seq<firstSequence))firstSequence=seq;
        if(seq>0) {
            long[] thread=threadTotals.computeIfAbsent(row.number("thread_id"),key->new long[7]);
            for(int i=0;i<CATEGORIES.length;i++)if(matchesCategory(row.type,row.text("access"),CATEGORIES[i])){categoryTotals[i]++;thread[i]++;}
        }
        byte[] captured=null;
        if(row.type==5 || row.type==6) {
            try { captured=row.bytes("value_hex"); } catch(IllegalArgumentException e) { throw new IOException("Invalid captured bytes",e); }
            if(row.type==5 && (row.number("requested_size")<captured.length || row.number("requested_size")>0xffffffffL)) throw new IOException("Invalid memory width");
            if(!Set.of("read","read_before","write_before","write_after","prefetch").contains(row.text("access"))) throw new IOException("Invalid access");
        }
        byte[] payload=row.encode();
        if(row.type==3) {instructionInsert.setLong(1,row.number("instruction_id"));instructionInsert.setLong(2,row.number("module_id"));instructionInsert.setLong(3,row.number("module_offset"));instructionInsert.setBytes(4,payload);instructionInsert.setString(5,row.text("routine"));instructionInsert.setString(6,row.text("disassembly"));instructionInsert.setString(7,row.text("routine").toLowerCase(Locale.ROOT));instructionInsert.setString(8,row.text("disassembly").toLowerCase(Locale.ROOT));instructionInsert.addBatch();}
        long address=row.number(row.type==5?"memory_address":row.type==2?"base":"address");
        BigDecimal base=unsigned(address), end=base.add(BigDecimal.valueOf(row.type==5?row.number("requested_size"):0));
        insert.setInt(1,row.type); insert.setLong(2,seq); insert.setLong(3,row.number("thread_id"));
        insert.setLong(4,row.number("instruction_id")); insert.setLong(5,row.number("module_id")); insert.setLong(6,row.number("module_offset"));
        insert.setBigDecimal(7,base); insert.setBigDecimal(8,end); insert.setLong(9,row.number("register_id")); insert.setString(10,row.text("access"));
        insert.setLong(11,row.number("call_id")); insert.setBigDecimal(12,unsigned(row.number("target_address"))); insert.setBytes(13,payload);insert.setBytes(14,captured); insert.addBatch();
        if(++pending>=2048) flush();
    }
    private void flush() throws SQLException { instructionInsert.executeBatch();insert.executeBatch(); db.commit(); pending=0; }
    public static BigDecimal unsigned(long n) { return new BigDecimal(Long.toUnsignedString(n)); }
    public List<Row> rows(String where, int limit, Object... args) throws Exception {
        List<Row> result=new ArrayList<>();
        try(PreparedStatement p=prepare("SELECT payload FROM evidence WHERE "+where+" FETCH FIRST "+limit+" ROWS ONLY")) {
            bind(p,args); try(ResultSet r=p.executeQuery()) { while(r.next()) result.add(Row.decode(r.getBytes(1))); }
        }
        return result;
    }
    private static void bind(PreparedStatement p,Object... args) throws SQLException { for(int i=0;i<args.length;i++) p.setObject(i+1,args[i]); }
    public List<Event> events(String where,int limit,Object... args) throws Exception {
        List<Object> key=new ArrayList<>(List.of("events",where,limit));Collections.addAll(key,args);List<Event> cached=eventCache.get(key);if(cached!=null){QueryControl.check();return cached;}
        List<Event> result=eventPage(where,limit,0,args);eventCache.put(key,result);return result;
    }
    private List<Event> eventPage(String where,int limit,long offset,Object... args) throws Exception {
        List<Event> result=new ArrayList<>();
        if(!where.contains("i.")) {
            String hint=where.startsWith("e.seq")?(where.contains("e.tid=?") && !where.contains("?<0")?" USE INDEX(idx_tid_seq)":" USE INDEX(idx_seq)"):"";
            try(PreparedStatement p=prepare("SELECT e.payload FROM evidence e"+hint+" WHERE "+where+" OFFSET "+offset+" ROWS FETCH NEXT "+limit+" ROWS ONLY")) {
                bind(p,args);try(ResultSet r=p.executeQuery()){while(r.next())result.add(hydrate(Row.decode(r.getBytes(1))));}
            }
            return result;
        }
        try(PreparedStatement p=prepare("SELECT e.payload,i.payload FROM evidence e LEFT JOIN instructions i ON e.iid=i.iid WHERE "+where+" OFFSET "+offset+" ROWS FETCH NEXT "+limit+" ROWS ONLY")) {
            bind(p,args); try(ResultSet r=p.executeQuery()) { while(r.next()) { byte[] inst=r.getBytes(2);Row row=Row.decode(r.getBytes(1));if(row.type==6)row.field("register_name",registerNames.getOrDefault(row.number("register_id"),"register #"+row.text("register_id")));result.add(new Event(row,inst==null?null:Row.decode(inst))); } }
        }
        return result;
    }
    public List<Row> modules() throws Exception { return rows("kind=2 AND payload IS NOT NULL ORDER BY seq",100000).stream().filter(r->r.flag("loaded")).toList(); }
    public List<Long> threads() throws SQLException {
        return List.copyOf(recordedThreads);
    }
    public Row instruction(long iid) throws Exception {
        if(iid==0)return null;
        if(instructionCache.containsKey(iid))return copyRow(instructionCache.get(iid));
        try(PreparedStatement p=prepare("SELECT payload FROM instructions WHERE iid=?")) { p.setLong(1,iid); try(ResultSet r=p.executeQuery()) {Row row=r.next()?Row.decode(r.getBytes(1)):null;instructionCache.put(iid,row);return copyRow(row);} }
    }
    private static Row copyRow(Row value){if(value==null)return null;Row copy=new Row(value.type);copy.putAll(value);return copy;}
    private Event hydrate(Row row) throws Exception {if(row.type==6)row.field("register_name",registerName(row.number("register_id")));return new Event(row,instruction(row.number("instruction_id")));}
    String registerName(long id){return registerNames.getOrDefault(id,"register #"+id);}
    Event searchEvent(long sequence) throws Exception {return hydrate(rows("seq=?",1,sequence).get(0));}
    Event searchEvent(byte[] payload) throws Exception {return hydrate(Row.decode(payload));}

    private TraceStore(TraceStore parent) throws Exception {
        owner=parent;eventCache=parent.eventCache;source=parent.source;label=parent.label;directory=parent.directory;cache=parent.cache;timelineIndex=new TimelineIndex(directory);loaded=true;
        db=connect(directory);
        try {
            db.setAutoCommit(false);try(Statement s=statement()){s.execute("SET LAZY_QUERY_EXECUTION TRUE");}
            captureDiagnostics=parent.captureDiagnostics;missingSequences=parent.missingSequences;count=parent.count;firstSequence=parent.firstSequence;lastSequence=parent.lastSequence;finished=parent.finished;incomplete=parent.incomplete;registerNames.putAll(parent.registerNames);recordedThreads.addAll(parent.recordedThreads);maxMemoryWidth=parent.maxMemoryWidth;capturedSamples=parent.capturedSamples;timelineCounts.putAll(parent.timelineCounts);
        }catch(Exception e){try{db.close();}catch(Exception close){e.addSuppressed(close);}throw e;}
    }
    public synchronized TraceStore openSearch() throws Exception {if(closed)throw new IOException("Run was unloaded");TraceStore child=new TraceStore(this);searchLeases++;return child;}
    public List<Event> at(long module,long offset,long thread,long cursor,int limit) throws Exception {
        PriorityQueue<Event> newest=new PriorityQueue<>(Comparator.comparingLong(Event::sequence));
        try(PreparedStatement p=prepare("SELECT iid FROM instructions WHERE mid=? AND off=?")) {
            bind(p,module,offset);try(ResultSet r=p.executeQuery()){while(r.next()) {
                QueryControl.check();long iid=r.getLong(1);
                for(Event e:events("e.iid=? AND e.seq>0 AND e.seq<=?"+(thread<0?"":" AND e.tid=?")+" ORDER BY e.seq DESC",limit,thread<0?new Object[]{iid,cursor}:new Object[]{iid,cursor,thread})) {
                    newest.add(e);if(newest.size()>limit)newest.poll();
                }
            }}
        }
        List<Event> result=new ArrayList<>(newest);result.sort(Comparator.comparingLong(Event::sequence).reversed());return result;
    }
    public List<Event> historyMemory(long address,int size,long cursor,boolean writes,int limit) throws Exception {
        BigDecimal start=unsigned(address), end=start.add(BigDecimal.valueOf(size));
        BigDecimal lower=start.subtract(BigDecimal.valueOf(maxMemoryWidth)).max(BigDecimal.ZERO);
        return events("e.kind=5 AND e.addr>=? AND e.addr<? AND e.endaddr>? AND e.seq<=?"+(writes?" AND e.access IN('write_before','write_after')":" AND e.access<>'prefetch'")+" ORDER BY e.seq DESC",limit,lower,end,start,cursor);
    }
    public List<Event> historyRegister(String name,long thread,long cursor,boolean writes,int limit) throws Exception {
        long id=-1;
        for(var register:registerNames.entrySet())if(register.getValue().equalsIgnoreCase(name)){id=register.getKey();break;}
        if(id<0 || thread<0) return List.of();
        return events("e.kind=6 AND e.reg=? AND e.tid=? AND e.seq<=?"+(writes?" AND e.access IN('write_before','write_after')":"")+" ORDER BY e.seq DESC",limit,id,thread,cursor);
    }
    public List<Event> calls(long target,long thread,long cursor,int limit) throws Exception {
        return events("e.kind=7 AND e.target=? AND e.seq<=?"+(thread<0?"":" AND e.tid=?")+" ORDER BY e.seq DESC",limit,thread<0?new Object[]{unsigned(target),cursor}:new Object[]{unsigned(target),cursor,thread});
    }
    public Row returned(long call,long thread,long cursor) throws Exception {
        List<Row> r=rows("kind=8 AND cid=? AND tid=? AND seq<=? ORDER BY seq DESC",1,call,thread,cursor);
        return r.isEmpty()?null:r.get(0);
    }
    public List<Event> activeCalls(long thread,long cursor,int limit) throws Exception {
        if(thread<0)return List.of();
        long boundary=0;
        try(PreparedStatement p=prepare("SELECT seq FROM evidence WHERE kind=13 AND tid=? AND seq<=? ORDER BY seq DESC FETCH FIRST 1 ROW ONLY")){bind(p,thread,cursor);try(ResultSet r=p.executeQuery()){if(r.next())boundary=r.getLong(1);}}
        List<Long> sequences=new ArrayList<>();
        try(PreparedStatement p=prepare("SELECT seq FROM call_lifetimes WHERE tid=? AND seq>? AND seq<? AND (returned IS NULL OR returned>?) ORDER BY seq DESC FETCH FIRST "+limit+" ROWS ONLY")) {
            bind(p,thread,boundary,cursor,cursor);try(ResultSet r=p.executeQuery()){while(r.next()){QueryControl.check();sequences.add(r.getLong(1));}}
        }
        return eventsAtSequences(sequences.stream().mapToLong(Long::longValue).toArray());
    }
    public String transition(Event event) throws Exception {
        Row after=event.row();
        if(!after.text("access").equals("write_after"))return "";
        List<Event> candidates=after.type==5
            ? events("e.kind=5 AND e.iid=? AND e.tid=? AND e.addr=? AND e.seq<? AND e.access='write_before' ORDER BY e.seq DESC",256,after.number("instruction_id"),after.number("thread_id"),unsigned(after.number("memory_address")),event.sequence())
            : events("e.kind=6 AND e.iid=? AND e.tid=? AND e.reg=? AND e.seq<? AND e.access='write_before' ORDER BY e.seq DESC",1,after.number("instruction_id"),after.number("thread_id"),after.number("register_id"),event.sequence());
        for(Event candidate:candidates) {
            Row before=candidate.row();
            if(after.type==5 && (!before.text("operand_index").equals(after.text("operand_index")) || !before.text("element_index").equals(after.text("element_index"))))continue;
            if(!rows("kind=4 AND iid=? AND tid=? AND seq>? AND seq<?",1,after.number("instruction_id"),after.number("thread_id"),candidate.sequence(),event.sequence()).isEmpty())return "Before-write sample belongs to an earlier execution; not paired.";
            byte[] a=after.bytes("value_hex"), b=before.bytes("value_hex");int changed=0;for(int i=0;i<Math.min(a.length,b.length);i++)if(a[i]!=b[i])changed++;
            return "Before #"+candidate.sequence()+": "+before.text("value_hex")+"\nAfter #"+event.sequence()+": "+after.text("value_hex")+"\n"+changed+" changed bytes among "+Math.min(a.length,b.length)+" bytes captured in both samples. Uncaptured bytes are unknown.";
        }
        return "No corresponding before-write sample was captured.";
    }
    public record Coverage(String routine,long instructions,long executions,Row sample) {}
    private record CoverageTotal(long iid,long executions) {}
    public List<Coverage> coverage(long module,int limit) throws Exception {
        if(limit<=0)return List.of();

        Comparator<CoverageTotal> worst=Comparator.comparingLong(CoverageTotal::executions).thenComparing(Comparator.comparingLong(CoverageTotal::iid).reversed());
        PriorityQueue<CoverageTotal> top=new PriorityQueue<>(Math.min(limit,1024),worst);
        try(PreparedStatement p=prepare("SELECT iid,executions FROM coverage_modules WHERE mid=?")) {
            p.setLong(1,module);try(ResultSet r=p.executeQuery()){while(r.next()){QueryControl.check();CoverageTotal candidate=new CoverageTotal(r.getLong(1),r.getLong(2));if(top.size()<limit)top.add(candidate);else if(worst.compare(candidate,top.peek())>0){top.poll();top.add(candidate);}}}
        }
        List<CoverageTotal> totals=new ArrayList<>(top);totals.sort(Comparator.comparingLong(CoverageTotal::executions).reversed().thenComparingLong(CoverageTotal::iid));
        if(totals.isEmpty())return List.of();
        Map<Long,Row> samples=new HashMap<>();List<Long> missing=new ArrayList<>();
        for(CoverageTotal total:totals){if(instructionCache.containsKey(total.iid()))samples.put(total.iid(),copyRow(instructionCache.get(total.iid())));else missing.add(total.iid());}
        if(!missing.isEmpty()) {
            String placeholders=String.join(",",Collections.nCopies(missing.size(),"?"));
            try(PreparedStatement p=prepare("SELECT iid,payload FROM instructions WHERE iid IN ("+placeholders+")")) {
                for(int i=0;i<missing.size();i++)p.setLong(i+1,missing.get(i));
                try(ResultSet r=p.executeQuery()){while(r.next()){QueryControl.check();long iid=r.getLong(1);Row row=Row.decode(r.getBytes(2));instructionCache.put(iid,row);samples.put(iid,copyRow(row));}}
            }
        }
        List<Coverage> result=new ArrayList<>(totals.size());for(CoverageTotal total:totals){Row row=samples.get(total.iid());if(row!=null)result.add(new Coverage(row.text("routine"),1,total.executions(),row));}return result;
    }
    public long executionCount(long module,long offset,long thread) throws SQLException {
        try(PreparedStatement p=prepare("SELECT COALESCE(SUM(e.executions),0) FROM execution_counts e JOIN instructions i ON e.iid=i.iid WHERE i.mid=? AND i.off=?"+(thread<0?"":" AND e.tid=?"))) {
            bind(p,thread<0?new Object[]{module,offset}:new Object[]{module,offset,thread}); try(ResultSet r=p.executeQuery()) { r.next(); return r.getLong(1); }
        }
    }
    public List<Event> timeline(long cursor,long thread,String kind,boolean forward,int limit) throws Exception {
        return timelinePage(cursor,thread,kind,forward,false,limit);
    }
    Connection searchDatabase() {return db;}
    record SearchSample(long sequence,int type,long thread,long iid,long address,long register,String access,byte[] data) {}
    final class SearchCursor implements AutoCloseable {
        final PreparedStatement statement;
        ResultSet rows;
        final List<ValueIndex.Range> ranges;
        int range;
        SearchSample sample;
        byte[] detailPayload;
        SearchCursor(TraceSearch.Query q) throws Exception {
            try(Statement s=statement()){s.execute("SET LAZY_QUERY_EXECUTION TRUE");}
            List<ValueIndex.Range> candidates=new ValueIndex(directory).candidates(TraceSearch.candidateGrams(q),Math.max(1,q.start()),q.end());
            ranges=candidates==null?List.of(new ValueIndex.Range(Math.max(1,q.start()),q.end())):candidates;
            StringBuilder where=new StringBuilder("e.seq>=? AND e.seq<=?");List<Object> args=new ArrayList<>(List.of(Math.max(1,q.start()),q.end()));
            if(q.mode()!=TraceSearch.Mode.DETAILS)where.append(" AND e.kind IN(5,6) AND e.access<>'prefetch'");
            if(q.writesOnly())where.append(" AND e.kind IN(5,6) AND e.access='write_after'");
            if(q.thread()>=0){where.append(" AND e.tid=?");args.add(q.thread());}
            where.append(timelineFilter(q.category()));
            String hint=q.thread()>=0?"idx_tid_seq":"idx_seq";

            if(q.addressStart()!=null || q.addressEnd()!=null){where.append(" AND e.kind=5");if(candidates==null && q.addressStart()!=null && q.addressEnd()!=null && unsigned(q.addressEnd()).subtract(unsigned(q.addressStart())).compareTo(BigDecimal.valueOf(4096))<=0)hint="idx_kind_addr_seq";}
            if(q.addressStart()!=null){where.append(" AND e.endaddr>?");args.add(unsigned(q.addressStart()));
                where.append(" AND e.addr>=?");args.add(unsigned(q.addressStart()).subtract(BigDecimal.valueOf(maxMemoryWidth)).max(BigDecimal.ZERO));}
            if(q.addressEnd()!=null){where.append(" AND e.addr<=?");args.add(unsigned(q.addressEnd()));}
            if(!q.register().isEmpty()){long id=-1;for(var r:registerNames.entrySet())if(r.getValue().equalsIgnoreCase(q.register())){id=r.getKey();break;}where.append(" AND e.kind=6 AND e.reg=?");args.add(id);if(q.thread()>=0)hint="idx_kind_reg_tid_seq";}
            if(!q.function().isEmpty() || !q.instruction().isEmpty()) {
                StringBuilder dictionary=new StringBuilder("SELECT iid FROM instructions WHERE 1=1");List<Object> dictionaryArgs=new ArrayList<>();
                if(!q.function().isEmpty()){dictionary.append(" AND LOCATE(?,").append(q.matchCase()?"routine":"routine_fold").append(")>0");dictionaryArgs.add(q.matchCase()?q.function():q.function().toLowerCase(Locale.ROOT));}
                if(!q.instruction().isEmpty()){dictionary.append(" AND LOCATE(?,").append(q.matchCase()?"disassembly":"disassembly_fold").append(")>0");dictionaryArgs.add(q.matchCase()?q.instruction():q.instruction().toLowerCase(Locale.ROOT));}
                boolean any;try(PreparedStatement p=prepare(dictionary+" FETCH FIRST 1 ROW ONLY")){bind(p,dictionaryArgs.toArray());try(ResultSet r=p.executeQuery()){any=r.next();}}
                if(any){where.append(" AND e.iid IN(").append(dictionary).append(')');args.addAll(dictionaryArgs);}else where.append(" AND 1=0");
            }
            statement=prepare("SELECT e.seq,e.kind,e.tid,e.iid,e.addr,e.reg,e.access,e.captured,e.endaddr,"+(q.mode()==TraceSearch.Mode.DETAILS?"e.payload":"NULL")+" FROM evidence e USE INDEX("+hint+") WHERE "+where+" ORDER BY e.seq",ResultSet.TYPE_FORWARD_ONLY,ResultSet.CONCUR_READ_ONLY);
            try{bind(statement,args.toArray());statement.setFetchSize(512);openRange();}catch(Exception e){statement.close();throw e;}
        }
        boolean next(TraceSearch.Query q,java.util.function.BooleanSupplier cancelled) throws Exception {
            if(cancelled.getAsBoolean())return false;
            QueryControl.check();while(rows!=null && !rows.next()){rows.close();rows=null;if(cancelled.getAsBoolean())return false;openRange();}if(rows==null)return false;
            sample=new SearchSample(rows.getLong(1),rows.getInt(2),rows.getLong(3),rows.getLong(4),rows.getBigDecimal(5).longValue(),rows.getLong(6),rows.getString(7),rows.getBytes(8));detailPayload=rows.getBytes(10);return true;
        }
        private void openRange()throws SQLException{QueryControl.check();if(range>=ranges.size()){rows=null;return;}ValueIndex.Range next=ranges.get(range++);statement.setLong(1,next.first());statement.setLong(2,next.last());rows=statement.executeQuery();}
        @Override public void close() throws SQLException {try{if(rows!=null)rows.close();}finally{statement.close();}}
    }
    SearchCursor scanSearch(TraceSearch.Query q) throws Exception {return new SearchCursor(q);}
    private static boolean matchesCategory(int type,String access,String category) {
        return switch(category){case "Capture diagnostics"->type==18;case "Writes"->(type==5 || type==6) && access.equals("write_after");case "Calls / returns"->type==7 || type==8;case "Control flow"->type==7 || type==8 || type==11 || type==13;case "Memory lifetime"->type==15;case "System / process"->type==9 || type==12 || type==13 || type==17;default->true;};
    }

    public List<Event> timelineThrough(long cursor,long thread,String kind,int limit) throws Exception {
        return timelinePage(cursor,thread,kind,false,true,limit);
    }
    private List<Event> timelinePage(long cursor,long thread,String kind,boolean forward,boolean inclusive,int limit) throws Exception {
        long position=timelineIndex.lowerBound(thread,kind,cursor);
        if(forward)return eventsAtSequences(timelineIndex.sequences(thread,kind,position,limit));
        if(inclusive){long[] at=timelineIndex.sequences(thread,kind,position,1);if(at.length>0 && at[0]==cursor)position++;}
        long start=Math.max(0,position-limit);List<Event> result=eventsAtSequences(timelineIndex.sequences(thread,kind,start,(int)(position-start)));Collections.reverse(result);return result;
    }
    private static String timelineFilter(String kind) {
        return switch(kind) {case "Capture diagnostics"->" AND e.kind=18";case "Writes"->" AND e.kind IN(5,6) AND e.access='write_after'"; case "Calls / returns"->" AND e.kind IN(7,8)"; case "Control flow"->" AND e.kind IN(7,8,11,13)"; case "Memory lifetime"->" AND e.kind=15"; case "System / process"->" AND e.kind IN(9,12,13,17)"; default->"";};
    }
    public record TimelinePage(long page,long pages,long total,List<Event> events) {}
    public TimelinePage numberedTimeline(long requested,long thread,String kind,int size) throws Exception {
        if(size<1)throw new IllegalArgumentException("Page size must be positive");
        long total=timelineIndex.count(thread,kind),pages=total==0?0:1+(total-1)/size;
        long page=Math.max(1,Math.min(requested,pages));
        return new TimelinePage(page,pages,total,eventsAtSequences(timelineIndex.sequences(thread,kind,(page-1)*size,size)));
    }
    public TimelinePage timelineAtMoment(long cursor,long thread,String kind,int size) throws Exception {
        if(size<1)throw new IllegalArgumentException("Page size must be positive");
        return numberedTimeline(1+timelineIndex.lowerBound(thread,kind,cursor)/size,thread,kind,size);
    }
    private List<Event> eventsAtSequences(long[] sequences) throws Exception {
        List<Object> key=new ArrayList<>(sequences.length+1);key.add("sequences");for(long seq:sequences)key.add(seq);List<Event> cached=eventCache.get(key);if(cached!=null){QueryControl.check();return cached;}
        List<Event> events=new ArrayList<>(sequences.length);
        try(PreparedStatement p=prepare("SELECT payload FROM evidence USE INDEX(idx_seq) WHERE seq=?")) {
            for(long sequence:sequences){QueryControl.check();p.setLong(1,sequence);try(ResultSet r=p.executeQuery()){if(!r.next())throw new IOException("Missing prepared event "+sequence);events.add(hydrate(Row.decode(r.getBytes(1))));}}
        }
        eventCache.put(key,events);return events;
    }
    @Override public synchronized void close() throws Exception {
        if(closed)return;closed=true;
        try {timelineIndex.close();}finally{try{db.close();}finally{if(owner!=null)owner.releaseSearch();else if(searchLeases==0)cache.release();}}
    }
    private synchronized void releaseSearch() throws Exception {searchLeases--;if(closed && searchLeases==0)cache.release();}
    @Override public String toString() { return label; }
}

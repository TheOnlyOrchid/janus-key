package janus.trace;

import java.io.*;
import java.nio.*;
import java.nio.channels.FileChannel;
import java.nio.file.*;
import java.sql.*;
import java.util.*;

final class TimelineIndex implements AutoCloseable {
    static final String[] CATEGORIES = {"All events", "Writes", "Calls / returns", "Control flow", "Memory lifetime", "System / process", "Capture diagnostics"};
    private final Path directory;
    private final LinkedHashMap<String,FileChannel> channels = new LinkedHashMap<>(32,.75f,true);
    TimelineIndex(Path directory) { this.directory = directory.resolve("timeline"); }
    static int category(String name) { for (int i=0;i<CATEGORIES.length;i++) if(CATEGORIES[i].equals(name))return i; return 0; }
    static boolean matches(int kind, String access, int category) {
        return switch(category) {
            case 1 -> (kind==5 || kind==6) && access.equals("write_after");
            case 2 -> kind==7 || kind==8;
            case 3 -> kind==7 || kind==8 || kind==11 || kind==13;
            case 4 -> kind==15;
            case 5 -> kind==9 || kind==12 || kind==13 || kind==17;
            case 6 -> kind==18;
            default -> true;
        };
    }
    private static String key(long thread,int category) { return thread+"-"+category+".seq"; }
    void build(Connection db, TraceStore.LoadProgress progress, long total) throws Exception {
        Files.createDirectories(directory);
        LinkedHashMap<String,DataOutputStream> outputs=new LinkedHashMap<>(64,.75f,true);
        long seen=0, previous=0;
        try(Statement setup=QueryControl.track(db.createStatement())){setup.execute("SET LAZY_QUERY_EXECUTION TRUE");}
        try (Statement statement=QueryControl.track(db.createStatement());
             ResultSet rows=statement.executeQuery("SELECT seq,kind,tid,access FROM evidence USE INDEX(idx_seq) WHERE seq>0 ORDER BY seq")) {
            while(rows.next()) {
                QueryControl.check(); long seq=rows.getLong(1), thread=rows.getLong(3);
                if(seq==previous)throw new IOException("Duplicate dynamic sequence "+seq);
                previous=seq; int kind=rows.getInt(2); String access=rows.getString(4);
                for(int c=0;c<CATEGORIES.length;c++)if(matches(kind,access,c)) {
                    for(long tid:new long[]{-1,thread}) {
                        String key=key(tid,c); DataOutputStream out=outputs.get(key);
                        if(out==null) {
                            if(outputs.size()>=64){var first=outputs.entrySet().iterator();var entry=first.next();entry.getValue().close();first.remove();}
                            out=new DataOutputStream(new BufferedOutputStream(Files.newOutputStream(directory.resolve(key),StandardOpenOption.CREATE,StandardOpenOption.APPEND),65536));outputs.put(key,out);
                        }
                        out.writeLong(seq);
                    }
                }
                if((++seen&16383)==0)progress.update("Preparing direct timeline navigation",seen,total);
            }
        } finally { closeAll(outputs.values()); }
        progress.update("Preparing direct timeline navigation",seen,total);
    }
    private FileChannel channel(long thread,String category) throws IOException {
        String key=key(thread,category(category));FileChannel channel=channels.get(key);
        if(channel==null) {
            Path path=directory.resolve(key);if(!Files.exists(path))return null;
            if(channels.size()>=32){var first=channels.entrySet().iterator();var entry=first.next();entry.getValue().close();first.remove();}
            channel=FileChannel.open(path,StandardOpenOption.READ);channels.put(key,channel);
        }
        return channel;
    }
    long count(long thread,String category) throws IOException {FileChannel c=channel(thread,category);if(c==null)return 0;long size=c.size();if(size%8!=0)throw new IOException("Incomplete timeline postings");return size/8;}
    long lowerBound(long thread,String category,long sequence) throws IOException {
        FileChannel c=channel(thread,category);if(c==null)return 0;
        long lo=0,hi=c.size()/8;ByteBuffer b=ByteBuffer.allocate(8);
        while(lo<hi){QueryControl.check();long mid=lo+(hi-lo)/2;b.clear();read(c,b,mid*8);b.flip();if(b.getLong()<sequence)lo=mid+1;else hi=mid;}
        return lo;
    }
    long[] sequences(long thread,String category,long ordinal,int size) throws IOException {
        FileChannel c=channel(thread,category);if(c==null)return new long[0];
        int n=(int)Math.max(0,Math.min(size,c.size()/8-ordinal));ByteBuffer b=ByteBuffer.allocate(Math.multiplyExact(n,8));read(c,b,ordinal*8);b.flip();
        long[] values=new long[n];for(int i=0;i<n;i++)values[i]=b.getLong();return values;
    }
    private static void read(FileChannel c,ByteBuffer b,long position) throws IOException {
        while(b.hasRemaining()){QueryControl.check();int n=c.read(b,position);if(n<0)throw new EOFException("Incomplete timeline index");position+=n;}
    }
    private static void closeAll(Collection<? extends Closeable> resources) throws IOException {IOException failure=null;for(Closeable resource:resources)try{resource.close();}catch(IOException e){if(failure==null)failure=e;else failure.addSuppressed(e);}if(failure!=null)throw failure;}
    @Override public void close() throws IOException {try{closeAll(channels.values());}finally{channels.clear();}}
}

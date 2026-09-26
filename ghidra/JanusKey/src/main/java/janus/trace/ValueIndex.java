package janus.trace;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.file.*;
import java.security.*;
import java.sql.*;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

final class ValueIndex {
    private static final long MAGIC=0x4a4b56414c554531L;
    private static final int WORDS=1024, CHUNK=4096, RECORD=16+WORDS*8;
    private static final Map<Path,ReentrantLock> LOCKS=new WeakHashMap<>();
    record Range(long first,long last) {}
    private final Path directory,file;
    ValueIndex(Path directory){this.directory=directory;file=directory.resolve("values.v1");}
    void ensure(Connection db,TraceStore.LoadProgress progress,long total) throws Exception {
        ReentrantLock lock;synchronized(LOCKS){lock=LOCKS.computeIfAbsent(directory,p->new ReentrantLock());}
        while(!lock.tryLock(100,TimeUnit.MILLISECONDS))QueryControl.check();
        try {
            QueryControl.check();if(valid())return;
            progress.update("Preparing value-search summaries",0,total);
            Path staged=Files.createTempFile(directory,"values-",".pending");
            try {
                MessageDigest digest=MessageDigest.getInstance("SHA-256");long[] bits=new long[WORDS];long first=0,last=0,seen=0;int n=0;
                try(Statement setup=QueryControl.track(db.createStatement())){setup.execute("SET LAZY_QUERY_EXECUTION TRUE");}
                try(DataOutputStream out=new DataOutputStream(new DigestOutputStream(new BufferedOutputStream(Files.newOutputStream(staged)),digest));
                    Statement statement=QueryControl.track(db.createStatement());
                    ResultSet rows=statement.executeQuery("SELECT seq,captured FROM evidence USE INDEX(idx_seq) WHERE seq>0 AND kind IN(5,6) AND access<>'prefetch' ORDER BY seq")) {
                    out.writeLong(MAGIC);
                    while(rows.next()) {
                        QueryControl.check();long seq=rows.getLong(1);if(n==0)first=seq;last=seq;
                        byte[] data=rows.getBytes(2);if(data!=null)for(int i=0;i+2<data.length;i++){if((i&4095)==0)QueryControl.check();add(bits,gram(data,i));}
                        seen++;if(++n==CHUNK){write(out,first,last,bits);Arrays.fill(bits,0);n=0;progress.update("Preparing value-search summaries",seen,total);}
                    }
                    if(n>0)write(out,first,last,bits);
                }
                Files.write(staged,digest.digest(),StandardOpenOption.APPEND);
                try{Files.move(staged,file,StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);}
                catch(AtomicMoveNotSupportedException e){Files.move(staged,file,StandardCopyOption.REPLACE_EXISTING);}
            }finally{Files.deleteIfExists(staged);}
        }finally{lock.unlock();}
    }
    private boolean valid() throws Exception {return read(null,0,Long.MAX_VALUE)!=null;}
    List<Range> candidates(List<int[]> alternatives,long start,long end) throws Exception {
        if(alternatives==null || !Boolean.parseBoolean(System.getProperty("janus.search.index","true")))return null;
        return read(alternatives,start,end);
    }

    private List<Range> read(List<int[]> alternatives,long start,long end) throws Exception {
        if(!Files.isRegularFile(file))return null;
        long size;try{size=Files.size(file);}catch(IOException e){return null;}if(size<40 || (size-40)%RECORD!=0)return null;
        long chunks=(size-40)/RECORD;List<Range> result=new ArrayList<>();boolean previousMatched=false,tooMany=false;long previousLast=0;
        MessageDigest digest=MessageDigest.getInstance("SHA-256");
        try(InputStream raw=new BufferedInputStream(Files.newInputStream(file));DigestInputStream checked=new DigestInputStream(raw,digest);DataInputStream in=new DataInputStream(checked)) {
            if(in.readLong()!=MAGIC)return null;
            long[] bits=new long[WORDS];byte[] packed=new byte[WORDS*8];ByteBuffer values=ByteBuffer.wrap(packed);
            for(long c=0;c<chunks;c++) {
                QueryControl.check();long first=in.readLong(),last=in.readLong();if(first<=previousLast || last<first)return null;previousLast=last;
                in.readFully(packed);values.clear();for(int i=0;i<WORDS;i++)bits[i]=values.getLong();
                boolean match=last>=start && first<=end && (alternatives==null || matches(bits,alternatives));
                if(match && !tooMany) {
                    long a=Math.max(first,start),b=Math.min(last,end);
                    if(previousMatched){Range previous=result.remove(result.size()-1);result.add(new Range(previous.first,b));}
                    else {result.add(new Range(a,b));if(result.size()>4096){tooMany=true;result.clear();}}
                }
                previousMatched=match;
            }
            byte[] expected=digest.digest();checked.on(false);byte[] actual=in.readNBytes(32);
            if(actual.length!=32 || !MessageDigest.isEqual(expected,actual) || in.read()!=-1 || tooMany)return null;
            return result;
        }catch(IOException e){return null;}
    }
    static int gram(byte[] bytes,int i){return (Byte.toUnsignedInt(bytes[i])<<16)|(Byte.toUnsignedInt(bytes[i+1])<<8)|Byte.toUnsignedInt(bytes[i+2]);}
    private static int hash1(int gram){return Integer.rotateLeft(gram*0x9e3779b9,13)&65535;}
    private static int hash2(int gram){return ((gram*0x85ebca6b)^(gram>>>7))&65535;}
    private static void add(long[] bits,int gram){int a=hash1(gram),b=hash2(gram);bits[a>>>6]|=1L<<(a&63);bits[b>>>6]|=1L<<(b&63);}
    private static boolean contains(long[] bits,int gram){int a=hash1(gram),b=hash2(gram);return (bits[a>>>6]&(1L<<(a&63)))!=0 && (bits[b>>>6]&(1L<<(b&63)))!=0;}
    private static boolean matches(long[] bits,List<int[]> alternatives){for(int[] grams:alternatives){boolean all=true;for(int gram:grams)if(!contains(bits,gram)){all=false;break;}if(all)return true;}return false;}
    private static void write(DataOutputStream out,long first,long last,long[] bits)throws IOException{out.writeLong(first);out.writeLong(last);for(long word:bits)out.writeLong(word);}
}

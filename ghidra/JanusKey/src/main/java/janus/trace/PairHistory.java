package janus.trace;

import java.io.*;
import java.math.BigDecimal;
import java.nio.file.*;
import java.sql.*;
import java.util.*;

final class PairHistory implements AutoCloseable {
    record Key(int kind,BigDecimal storage,long thread,int offset,int encoding) {}
    private final Map<Key,Long> pending=new HashMap<>();
    private final int capacity;
    private Path directory;
    private Connection db;
    private PreparedStatement save,find,remove;
    PairHistory(){this(Integer.getInteger("janus.search.pairEntries",32768));}
    PairHistory(int capacity){this.capacity=Math.max(1,capacity);}
    Long get(Key key) throws SQLException {
        Long seq=pending.get(key);if(seq!=null || db==null)return seq;
        bind(find,key);try(ResultSet r=find.executeQuery()){return r.next()?r.getLong(1):null;}
    }
    void put(Key key,long sequence) throws Exception {pending.put(key,sequence);if(pending.size()>=capacity)flush();}
    void remove(Key key) throws SQLException {pending.remove(key);if(db!=null){bind(remove,key);remove.executeUpdate();}}
    private void flush() throws Exception {
        if(db==null) {
            directory=Files.createTempDirectory("janus-search-");
            db=DriverManager.getConnection("jdbc:h2:file:"+directory.resolve("pairs").toString().replace('\\','/')+";CACHE_SIZE=4096;DB_CLOSE_ON_EXIT=FALSE","sa","");
            db.setAutoCommit(false);
            try(Statement s=QueryControl.track(db.createStatement())){s.execute("CREATE TABLE pairs(kind INT,storage NUMERIC(20),tid BIGINT,byteoff INT,encoding INT,seq BIGINT,PRIMARY KEY(kind,storage,tid,byteoff,encoding))");}
            save=QueryControl.track(db.prepareStatement("MERGE INTO pairs VALUES(?,?,?,?,?,?)"));find=QueryControl.track(db.prepareStatement("SELECT seq FROM pairs WHERE kind=? AND storage=? AND tid=? AND byteoff=? AND encoding=?"));remove=QueryControl.track(db.prepareStatement("DELETE FROM pairs WHERE kind=? AND storage=? AND tid=? AND byteoff=? AND encoding=?"));
        }
        for(var entry:pending.entrySet()){QueryControl.check();bind(save,entry.getKey());save.setLong(6,entry.getValue());save.addBatch();}
        save.executeBatch();db.commit();pending.clear();
    }
    private static void bind(PreparedStatement p,Key k) throws SQLException {p.setInt(1,k.kind);p.setBigDecimal(2,k.storage);p.setLong(3,k.thread);p.setInt(4,k.offset);p.setInt(5,k.encoding);}
    @Override public void close() throws Exception {
        try {if(save!=null)save.close();if(find!=null)find.close();if(remove!=null)remove.close();}
        finally {try{if(db!=null)db.close();}finally{if(directory!=null)try(var paths=Files.walk(directory)){for(Path p:paths.sorted(Comparator.reverseOrder()).toList())Files.deleteIfExists(p);}}}
    }
}

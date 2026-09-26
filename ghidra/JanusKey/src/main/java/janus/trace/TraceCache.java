package janus.trace;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.channels.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;
import java.security.MessageDigest;
import java.util.*;

final class TraceCache {
    private static final String VERSION="4";

    private static final String ENGINE=engineVersion();
    private static final String READY="ready";
    private static final String MARKER=".janus-cache";
    private static final long DEFAULT_QUOTA=20L*1024*1024*1024;
    private static final Map<Path,Lease> OPEN=new HashMap<>();

    static Path root() {
        String configured=System.getProperty("janus.cache.dir");
        if(configured!=null && !configured.isBlank())return Path.of(configured).toAbsolutePath().normalize();
        String local=System.getenv("LOCALAPPDATA");
        return (local==null?Path.of(System.getProperty("user.home"),".cache"):Path.of(local)).resolve("JanusKey/indexes");
    }

    static String identity(Path source) throws Exception {
        Path selected=source.toAbsolutePath().normalize();
        Path binary=Files.isDirectory(selected)?selected.resolve("trace.jkt"):selected;
        List<Path> files;
        if(Files.isRegularFile(binary))files=List.of(binary);
        else {
            files=new ArrayList<>();
            for(int i=1;i<TraceReader.FILES.length;i++)files.add(selected.resolve(TraceReader.FILES[i]+".csv"));
        }
        StringBuilder text=new StringBuilder("janus-cache-").append(VERSION).append('\n');
        for(Path file:files) {
            Path absolute=file.toAbsolutePath().normalize();
            text.append(absolute).append('\t');
            if(Files.exists(absolute)) {
                BasicFileAttributes a=Files.readAttributes(absolute,BasicFileAttributes.class);
                text.append(absolute.toRealPath()).append('\t').append(a.fileKey()).append('\t').append(a.size()).append('\t').append(a.lastModifiedTime());
            } else text.append("missing");
            text.append('\n');
        }
        return text.toString();
    }

    private static String key(String identity) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(identity.getBytes(StandardCharsets.UTF_8)));
    }

    private static String engineVersion() {
        try {
            Class<?> constants=Class.forName("org.h2.engine.Constants");
            return "h2-"+constants.getField("VERSION").get(null);
        } catch(Exception|LinkageError ignored) {

            return "h2-unknown";
        }
    }

    static synchronized Lease acquire(Path source) throws Exception {
        String sourceIdentity=identity(source);
        String name=key(sourceIdentity);
        Path cacheRoot=root();
        Files.createDirectories(cacheRoot);
        Path lockRoot=cacheRoot.resolve("locks");
        Files.createDirectories(lockRoot);
        Path canonical=cacheRoot.resolve(name);
        Lease open=OPEN.get(canonical);
        if(open!=null && open.ready && !open.invalid) {
            open.references++;
            return open;
        }

        Lease lease=null;
        Gate gate=null;
        try {

            if(open==null)gate=tryLock(lockRoot.resolve(name+".lock"));
            Path directory=canonical;
            boolean temporary=false;
            if(gate==null) {
                temporary=true;
                PrivateEntry privateEntry=createPrivate(cacheRoot,lockRoot);
                directory=privateEntry.directory;
                gate=privateEntry.gate;
            } else {
                if(Files.isSymbolicLink(directory))throw new IOException("Cache entry is a symbolic link: "+directory);
                Files.createDirectories(directory);
            }
            lease=new Lease(directory,sourceIdentity,temporary,gate.path,gate.channel,gate.lock);
            gate=null;
            if(temporary) {
                writeMarker(directory);
            } else {
                inspectCanonical(lease);
            }
            OPEN.put(directory,lease);
            return lease;
        } catch(Exception failure) {
            if(lease!=null) {
                try { lease.release(); }
                catch(Exception cleanup) { failure.addSuppressed(cleanup); }
            } else if(gate!=null) {
                try { gate.close(); }
                catch(Exception cleanup) { failure.addSuppressed(cleanup); }
            }
            throw failure;
        }
    }

    private static void inspectCanonical(Lease lease) throws IOException {
        Path directory=lease.directory;
        Path manifest=directory.resolve("manifest.properties");
        boolean valid=false;
        if(regular(manifest)) {
            try(InputStream in=Files.newInputStream(manifest)) {
                lease.metadata.load(in);
                valid=isCompatible(lease.metadata) && lease.identity.equals(lease.metadata.getProperty("source")) && preparedArtifacts(directory);
            } catch(Exception malformed) {

                valid=false;
                lease.metadata.clear();
            }
        }
        if(valid) {

            Files.deleteIfExists(directory.resolve("manifest.pending"));
            lease.ready=true;
            lease.invalid=false;
            return;
        }
        lease.metadata.clear();
        clearEntry(directory);
        writeMarker(directory);
    }

    private static boolean isCompatible(Properties metadata) {
        String version=metadata.getProperty("version");
        if(!VERSION.equals(version))return false;
        String state=metadata.getProperty("state");
        if(state!=null && !READY.equals(state))return false;

        String engine=metadata.getProperty("engine");
        return engine==null || ENGINE.equals(engine);
    }

    private static boolean preparedArtifacts(Path directory) {
        return regular(directory.resolve("trace.mv.db")) && directory(directory.resolve("timeline"));
    }

    private static PrivateEntry createPrivate(Path cacheRoot,Path lockRoot) throws IOException {
        Path lockPath=Files.createTempFile(lockRoot,"private-",".lock");
        Gate gate=null;
        Path directory=null;
        try {
            gate=tryLock(lockPath);
            if(gate==null)throw new IOException("Could not lock private cache entry");
            String filename=lockPath.getFileName().toString();
            filename=filename.substring(0,filename.length()-".lock".length());
            directory=cacheRoot.resolve(filename);
            Files.createDirectory(directory);
            writeMarker(directory);
            return new PrivateEntry(directory,gate);
        } catch(Exception failure) {
            if(directory!=null) {
                try { clearEntry(directory); Files.deleteIfExists(directory); }
                catch(Exception cleanup) { failure.addSuppressed(cleanup); }
            }
            if(gate!=null) {
                try { gate.close(); }
                catch(Exception cleanup) { failure.addSuppressed(cleanup); }
            } else {
                try { Files.deleteIfExists(lockPath); }
                catch(Exception cleanup) { failure.addSuppressed(cleanup); }
            }
            if(failure instanceof IOException e)throw e;
            if(failure instanceof RuntimeException e)throw e;
            throw new IOException("Could not create private cache entry",failure);
        }
    }

    private record PrivateEntry(Path directory,Gate gate) {}

    private static Gate tryLock(Path path) throws IOException {
        FileChannel channel=FileChannel.open(path,StandardOpenOption.CREATE,StandardOpenOption.WRITE);
        try {
            FileLock lock;
            try { lock=channel.tryLock(); }
            catch(OverlappingFileLockException busy) { lock=null; }
            if(lock==null) {
                channel.close();
                return null;
            }
            return new Gate(path,channel,lock);
        } catch(IOException|RuntimeException failure) {
            try { channel.close(); }
            catch(IOException cleanup) { failure.addSuppressed(cleanup); }
            throw failure;
        }
    }

    private record Gate(Path path,FileChannel channel,FileLock lock) implements AutoCloseable {
        @Override public void close() throws IOException {
            IOException failure=null;
            try { if(lock.isValid())lock.release(); }
            catch(IOException e) { failure=e; }
            try { if(channel.isOpen())channel.close(); }
            catch(IOException e) { if(failure==null)failure=e; else failure.addSuppressed(e); }
            if(failure!=null)throw failure;
        }
    }

    static final class Lease implements AutoCloseable {
        final Path directory;
        final String identity;
        final boolean temporary;
        final Path lockPath;
        final FileChannel channel;
        final FileLock lock;
        final Properties metadata=new Properties();
        volatile boolean ready;
        volatile boolean invalid;
        int references=1;
        Lease(Path directory,String identity,boolean temporary,Path lockPath,FileChannel channel,FileLock lock) {
            this.directory=directory;this.identity=identity;this.temporary=temporary;this.lockPath=lockPath;this.channel=channel;this.lock=lock;
        }

        void publish(Path source,Properties values) throws Exception {
            if(!identity.equals(identity(source)))throw new IOException("Recording changed while it was being prepared; retry when recording is finished");
            if(!preparedArtifacts(directory))throw new IOException("Prepared data is incomplete; refusing to publish cache");
            Properties published=new Properties();
            published.putAll(values);
            published.setProperty("version",VERSION);
            published.setProperty("engine",ENGINE);
            published.setProperty("state",READY);
            published.setProperty("source",identity);
            Path staged=directory.resolve("manifest.pending");
            try {
                synchronized(TraceCache.class) {
                    if(invalid)throw new IOException("Cache lease was invalidated while it was being prepared");
                    writeProperties(staged,published);
                    try {
                        Files.move(staged,directory.resolve("manifest.properties"),StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);
                    } catch(AtomicMoveNotSupportedException e) {

                        Files.move(staged,directory.resolve("manifest.properties"),StandardCopyOption.REPLACE_EXISTING);
                    }
                    forceDirectory(directory);
                    metadata.clear();metadata.putAll(published);invalid=false;ready=true;
                }
            } catch(Exception failure) {
                try { Files.deleteIfExists(staged); }
                catch(Exception cleanup) { failure.addSuppressed(cleanup); }
                synchronized(TraceCache.class) { ready=false;invalid=true;metadata.clear(); }
                throw failure;
            }
        }

        void discard() throws IOException {
            synchronized(TraceCache.class) {
                ready=false;invalid=true;metadata.clear();
                IOException failure=null;
                for(String name:List.of("manifest.properties","manifest.pending")) {
                    try { Files.deleteIfExists(directory.resolve(name)); }
                    catch(IOException e) { if(failure==null)failure=e; else failure.addSuppressed(e); }
                }
                if(failure!=null)throw failure;
            }
        }

        void release() throws IOException {
            synchronized(TraceCache.class) {
                if(references<=0)return;
                if(--references>0)return;
                OPEN.remove(directory,this);
                IOException failure=null;
                try {
                    if(temporary || invalid || !ready || !preparedArtifacts(directory) || !regular(directory.resolve("manifest.properties"))) {
                        clearEntry(directory);
                        if(temporary)Files.deleteIfExists(directory);
                    } else {
                        Files.deleteIfExists(directory.resolve("manifest.pending"));
                        try { Files.setLastModifiedTime(directory.resolve("manifest.properties"),FileTime.fromMillis(System.currentTimeMillis())); }
                        catch(IOException ignored) {}
                    }
                } catch(IOException e) { failure=e; }
                try { new Gate(lockPath,channel,lock).close(); }
                catch(IOException e) { if(failure==null)failure=e; else failure.addSuppressed(e); }
                if(temporary) {
                    try { Files.deleteIfExists(lockPath); }
                    catch(IOException e) { if(failure==null)failure=e; else failure.addSuppressed(e); }
                }
                if(failure!=null)throw failure;
            }
        }

        @Override public void close() throws IOException { release(); }
    }

    private static void writeProperties(Path target,Properties values) throws IOException {
        ByteArrayOutputStream bytes=new ByteArrayOutputStream();
        values.store(bytes,"Janus Key prepared recording");
        byte[] data=bytes.toByteArray();
        try(FileChannel channel=FileChannel.open(target,StandardOpenOption.CREATE,StandardOpenOption.TRUNCATE_EXISTING,StandardOpenOption.WRITE)) {
            ByteBuffer buffer=ByteBuffer.wrap(data);
            while(buffer.hasRemaining())channel.write(buffer);
            channel.force(true);
        }
    }

    private static void writeMarker(Path directory) throws IOException {
        Path marker=directory.resolve(MARKER);
        if(regular(marker))return;
        byte[] data="Janus Key derived cache\n".getBytes(StandardCharsets.UTF_8);
        try(FileChannel channel=FileChannel.open(marker,StandardOpenOption.CREATE,StandardOpenOption.TRUNCATE_EXISTING,StandardOpenOption.WRITE)) {
            ByteBuffer buffer=ByteBuffer.wrap(data);
            while(buffer.hasRemaining())channel.write(buffer);
            channel.force(true);
        }
    }

    private static void forceDirectory(Path directory) throws IOException {
        try(FileChannel channel=FileChannel.open(directory,StandardOpenOption.READ)) { channel.force(true); }
        catch(UnsupportedOperationException|IOException ignored) {}
    }

    private static boolean regular(Path path) { return Files.isRegularFile(path,LinkOption.NOFOLLOW_LINKS); }
    private static boolean directory(Path path) { return Files.isDirectory(path,LinkOption.NOFOLLOW_LINKS); }

    private static void clearEntry(Path directory) throws IOException {
        if(Files.isSymbolicLink(directory)) { Files.deleteIfExists(directory); return; }
        if(!Files.exists(directory,LinkOption.NOFOLLOW_LINKS))return;
        if(!directory(directory)) { Files.deleteIfExists(directory); return; }
        try(var files=Files.walk(directory)) {
            for(Path path:files.sorted(Comparator.reverseOrder()).toList()) {
                if(path.equals(directory))continue;
                Files.deleteIfExists(path);
            }
        }
    }

    private static boolean cacheName(String name) {
        if(name.startsWith("private-"))return true;
        if(name.length()!=64)return false;
        for(int i=0;i<name.length();i++) {
            char c=name.charAt(i);
            if((c<'0'||c>'9')&&(c<'a'||c>'f'))return false;
        }
        return true;
    }

    private static List<Path> entries(Path root) throws IOException {
        try(var files=Files.list(root)) {
            return files.filter(p->directory(p) && cacheName(p.getFileName().toString())).toList();
        }
    }

    private static boolean recognized(Path entry) {
        return regular(entry.resolve(MARKER)) || regular(entry.resolve("manifest.properties")) || regular(entry.resolve("manifest.pending")) || regular(entry.resolve("trace.mv.db")) || directory(entry.resolve("timeline"));
    }

    private static boolean orphan(Path entry) {
        if(!recognized(entry))return false;
        Path manifest=entry.resolve("manifest.properties");
        if(!regular(manifest) || !preparedArtifacts(entry))return true;
        Properties metadata=new Properties();
        try(InputStream in=Files.newInputStream(manifest)) { metadata.load(in);return !isCompatible(metadata); }
        catch(Exception e) { return true; }
    }

    private static long entrySize(Path entry) throws IOException {
        if(!Files.exists(entry,LinkOption.NOFOLLOW_LINKS))return 0;
        try(var files=Files.walk(entry)) {
            long total=0;
            for(Path path:files.toList())if(regular(path)) {
                long size=Files.size(path);
                total=Long.MAX_VALUE-size<total?Long.MAX_VALUE:total+size;
            }
            return total;
        }
    }

    private static long add(long left,long right) { return Long.MAX_VALUE-right<left?Long.MAX_VALUE:left+right; }

    private static long lastUsed(Path directory) {
        try {
            Path manifest=directory.resolve("manifest.properties");
            if(regular(manifest))return Files.getLastModifiedTime(manifest,LinkOption.NOFOLLOW_LINKS).toMillis();
            return Files.getLastModifiedTime(directory,LinkOption.NOFOLLOW_LINKS).toMillis();
        } catch(IOException e) { return 0; }
    }

    private static boolean deleteUnused(Path root,Path entry) throws IOException {
        synchronized(TraceCache.class) {
            if(OPEN.containsKey(entry))return false;
            Gate gate=tryLock(root.resolve("locks").resolve(entry.getFileName()+".lock"));
            if(gate==null)return false;
            try {
                if(OPEN.containsKey(entry))return false;
                clearEntry(entry);
                Files.deleteIfExists(entry);
                return !Files.exists(entry,LinkOption.NOFOLLOW_LINKS);
            } finally { gate.close(); }
        }
    }

    private static long configuredQuota() {
        String value=System.getProperty("janus.cache.maxBytes");
        if(value==null || value.isBlank())return DEFAULT_QUOTA;
        try { return Math.max(0,Long.parseLong(value.trim())); }
        catch(NumberFormatException ignored) { return DEFAULT_QUOTA; }
    }

    static long quotaBytes() { return configuredQuota(); }

    static long cacheBytes() throws IOException {
        Path root=root();
        if(!directory(root))return 0;
        long total=0;
        for(Path entry:entries(root))total=add(total,entrySize(entry));
        return total;
    }

    static void clearUnused() throws IOException {
        Path root=root();
        if(!directory(root))return;
        Files.createDirectories(root.resolve("locks"));
        IOException failure=null;
        for(Path entry:entries(root)) {
            if(!recognized(entry))continue;
            try { deleteUnused(root,entry); }
            catch(IOException e) { if(failure==null)failure=e; else failure.addSuppressed(e); }
        }
        if(failure!=null)throw failure;
    }

    static void prune() throws IOException {
        Path root=root();
        if(!directory(root))return;
        Files.createDirectories(root.resolve("locks"));
        List<Path> all=entries(root);
        long total=0;
        Map<Path,Long> sizes=new HashMap<>();
        IOException failure=null;
        for(Path entry:all) {
            long size;
            try { size=entrySize(entry); }
            catch(IOException e) { size=0;if(failure==null)failure=e;else failure.addSuppressed(e); }
            sizes.put(entry,size);total=add(total,size);
        }

        List<Path> remaining=new ArrayList<>(all);
        for(Path entry:all)if(orphan(entry)) {
            try {
                if(deleteUnused(root,entry)) {
                    total=Math.max(0,total-sizes.getOrDefault(entry,0L));
                    remaining.remove(entry);
                }
            } catch(IOException e) { if(failure==null)failure=e;else failure.addSuppressed(e); }
        }
        if(total>configuredQuota()) {
            List<Path> oldest=remaining.stream().filter(TraceCache::recognized).collect(java.util.stream.Collectors.toCollection(ArrayList::new));
            oldest.sort(Comparator.comparingLong(TraceCache::lastUsed).thenComparing(Path::toString));
            for(Path entry:oldest) {
                if(total<=configuredQuota())break;
                try {
                    if(deleteUnused(root,entry))total=Math.max(0,total-sizes.getOrDefault(entry,0L));
                } catch(IOException e) { if(failure==null)failure=e;else failure.addSuppressed(e); }
            }
        }
        if(failure!=null)throw failure;
    }
}

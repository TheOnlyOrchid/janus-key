package janus.trace;

import com.sun.jna.*;
import com.sun.jna.ptr.PointerByReference;
import com.sun.jna.win32.StdCallLibrary;
import java.io.IOException;
import java.nio.file.Path;

public final class WindowsXpress implements TraceReader.Decompressor, AutoCloseable {
    public interface Cabinet extends StdCallLibrary {
        boolean CreateDecompressor(int algorithm, Pointer allocation, PointerByReference handle);
        boolean Decompress(Pointer handle, byte[] input, SizeT inputSize, byte[] output, SizeT capacity, Pointer written);
        boolean CloseDecompressor(Pointer handle);
    }
    public static class SizeT extends IntegerType {
        public SizeT() { this(0); }
        public SizeT(long value) { super(Native.SIZE_T_SIZE,value,true); }
    }
    private Cabinet api;
    private Pointer handle;
    @Override public byte[] decode(byte[] stored, int size) throws IOException {
        if(api==null) {
            if(!Platform.isWindows()) throw new IOException("XPRESS traces need Windows. Capture with -compression none or -format csv for other platforms.");
            try {
                String system=System.getenv("SystemRoot");
                api=Native.load(Path.of(system,"System32","cabinet.dll").toString(),Cabinet.class);
                PointerByReference ref=new PointerByReference();
                if(!api.CreateDecompressor(4,null,ref)) throw new IOException("Cannot initialize Windows XPRESS decompressor");
                handle=ref.getValue();
            } catch(LinkageError | RuntimeException e) { throw new IOException("Windows compression API unavailable",e); }
        }
        byte[] out=new byte[size];
        try(Memory written=new Memory(Native.SIZE_T_SIZE)) {
            if(!api.Decompress(handle,stored,new SizeT(stored.length),out,new SizeT(size),written)) throw new IOException("XPRESS decompression failed");
            long actual=Native.SIZE_T_SIZE==8?written.getLong(0):Integer.toUnsignedLong(written.getInt(0));
            if(actual!=size) throw new IOException("XPRESS decoded size mismatch");
        }
        return out;
    }
    @Override public void close() { if(handle!=null) { api.CloseDecompressor(handle); handle=null; } }
}

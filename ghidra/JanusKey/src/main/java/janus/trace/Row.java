package janus.trace;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

public final class Row extends LinkedHashMap<String, String> {
    public final int type;
    public Row(int type) { this.type = type; }
    public String text(String name) { return getOrDefault(name, ""); }
    public long number(String name) {
        String s = text(name);
        if (s.isEmpty()) return 0;
        return s.startsWith("0x") ? Long.parseUnsignedLong(s.substring(2), 16) : Long.parseUnsignedLong(s);
    }
    public boolean flag(String name) { return text(name).equals("true"); }
    public byte[] bytes(String name) { return HexFormat.of().parseHex(text(name)); }
    public Row field(String key, Object value) { put(key, String.valueOf(value)); return this; }
    public String describe() {
        StringBuilder b = new StringBuilder();
        forEach((k,v) -> b.append(k).append(": ").append(v).append('\n'));
        return b.toString();
    }
    public byte[] encode() throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (DataOutputStream d = new DataOutputStream(out)) {
            d.writeInt(type); d.writeInt(size());
            for (var e : entrySet()) { write(d, e.getKey()); write(d, e.getValue()); }
        }
        return out.toByteArray();
    }
    private static void write(DataOutputStream d, String s) throws IOException {
        byte[] b = s.getBytes(StandardCharsets.UTF_8); d.writeInt(b.length); d.write(b);
    }
    public static Row decode(byte[] bytes) throws IOException {
        try (DataInputStream d = new DataInputStream(new ByteArrayInputStream(bytes))) {
            Row r = new Row(d.readInt()); int count = d.readInt();
            if (count < 0 || count > 256) throw new IOException("Invalid index row");
            for (int i=0; i<count; i++) r.put(read(d), read(d));
            return r;
        }
    }
    private static String read(DataInputStream d) throws IOException {
        int n = d.readInt();
        if (n < 0 || n > d.available()) throw new IOException("Invalid index field");
        return new String(d.readNBytes(n), StandardCharsets.UTF_8);
    }
    public static String hex(long value) { return "0x" + Long.toUnsignedString(value, 16); }
}

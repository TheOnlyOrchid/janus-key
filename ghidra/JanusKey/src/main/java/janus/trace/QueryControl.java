package janus.trace;

import java.lang.reflect.*;
import java.sql.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;

public final class QueryControl {
    private static final ThreadLocal<QueryControl> CURRENT = new ThreadLocal<>();
    private static final ExecutorService CANCELLER = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "Janus Key cancellation"); t.setDaemon(true); return t;
    });
    private final AtomicBoolean stopped = new AtomicBoolean();
    private final Set<Statement> statements = Collections.newSetFromMap(new IdentityHashMap<>());
    private final long deadline;

    public QueryControl() { deadline = Long.MAX_VALUE; }
    public QueryControl(Duration budget) { deadline = System.nanoTime() + budget.toNanos(); }
    public boolean cancelled() { return stopped.get() || timedOut(); }
    public boolean timedOut() { return deadline != Long.MAX_VALUE && System.nanoTime() >= deadline; }
    public void cancel() {
        if(!stopped.compareAndSet(false,true))return;
        List<Statement> snapshot;
        synchronized (statements) { snapshot = List.copyOf(statements); }
        if(snapshot.isEmpty())return;

        CANCELLER.execute(() -> { for (Statement s : snapshot) try { s.cancel(); } catch (SQLException ignored) {} });
    }
    public Scope activate() {
        QueryControl previous = CURRENT.get(); CURRENT.set(this);
        return () -> { if (previous == null) CURRENT.remove(); else CURRENT.set(previous); };
    }
    public interface Scope extends AutoCloseable { @Override void close(); }
    public static void check() {
        QueryControl c = CURRENT.get();
        if (c != null && c.cancelled()) throw new CancellationException(c.timedOut() ? "Query time budget exceeded" : "Operation cancelled");
    }
    public static PreparedStatement track(PreparedStatement statement) throws SQLException {
        return track(statement, PreparedStatement.class);
    }
    public static Statement track(Statement statement) throws SQLException { return track(statement, Statement.class); }
    private static <T extends Statement> T track(T statement, Class<T> type) throws SQLException {
        QueryControl c = CURRENT.get();
        if (c == null) return statement;
        if (c.cancelled()) { statement.close(); check(); }
        if (c.deadline != Long.MAX_VALUE) statement.setQueryTimeout((int)Math.max(1, Math.min(Integer.MAX_VALUE, (c.deadline-System.nanoTime()+999_999_999L)/1_000_000_000L)));
        synchronized (c.statements) { c.statements.add(statement); }
        return type.cast(Proxy.newProxyInstance(QueryControl.class.getClassLoader(), new Class<?>[]{type}, (proxy, method, args) -> {
            try {
                if (method.getName().startsWith("execute")) check();
                return method.invoke(statement, args);
            } catch (InvocationTargetException e) { throw e.getCause(); }
            finally { if (method.getName().equals("close")) synchronized (c.statements) { c.statements.remove(statement); } }
        }));
    }
}

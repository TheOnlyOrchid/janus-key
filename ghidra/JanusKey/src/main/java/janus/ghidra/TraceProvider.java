package janus.ghidra;

import janus.trace.*;
import docking.*;
import docking.widgets.table.GTable;
import ghidra.framework.plugintool.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.util.ProgramLocation;
import ghidra.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.nio.file.*;
import java.util.List;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.Consumer;

final class TraceProvider extends ComponentProviderAdapter {
    private final JanusKeyPlugin plugin;
    private final JPanel panel=new JPanel(new BorderLayout(6,6));
    private final JComboBox<Run> runs=new JComboBox<>();
    private final JComboBox<Module> modules=new JComboBox<>();
    private final JComboBox<String> threads=new JComboBox<>();
    private final JComboBox<String> kind=new JComboBox<>(new String[]{"All events","Writes","Calls / returns","Control flow","Memory lifetime","System / process","Capture diagnostics"});
    private final JTextField sequence=new JTextField("0",14), watch=new JTextField(22);
    private final ProgressStatus status=new ProgressStatus();
    private final JLabel mapping=new JLabel("Open the matching program and select its recorded module.");
    private final JCheckBox follow=new JCheckBox("Follow code selection",true), writes=new JCheckBox("Writes only");
    private final JTabbedPane tabs=new JTabbedPane();
    private final TraceSearchPanel searchPanel;
    private final EventModel timelineModel=new EventModel(), historyModel=new EventModel();
    private final GTable timeline=new EvidenceTable(timelineModel), history=new EvidenceTable(historyModel);
    private final JTextArea detail=new JTextArea(), comparison=new JTextArea();
    private final EventModel stackModel=new EventModel();
    private final GTable stack=new EvidenceTable(stackModel);
    private final DefaultListModel<String> bookmarkLabels=new DefaultListModel<>();
    private final JList<String> bookmarkList=new JList<>(bookmarkLabels);
    private final List<Bookmark> bookmarks=new ArrayList<>();
    private final CoverageModel coverageModel=new CoverageModel();
    private final GTable coverageTable=new GTable(coverageModel);
    private final JLabel historyTitle=new JLabel("Hover a value and choose History, or enter rax / 0xADDRESS:SIZE.");
    private final JLabel timelineRange=new JLabel("Import a run to browse its recorded events.");
    private final ThreadPoolExecutor worker=executor("Janus Key queries",2);
    private final ExecutorService importWorker=executor("Janus Key preparation",1),analysisWorker=executor("Janus Key analysis",1),lifecycleWorker=executor("Janus Key files",1);
    private final Map<String,QueryJob> jobs=new HashMap<>();
    private boolean updatingSelection;
    private TraceStore.Event detailEvent;
    private long enrichedSequence=-1;
    private ProgramLocation pendingLocation;
    private final javax.swing.Timer followTimer=new javax.swing.Timer(125,e->{ProgramLocation loc=pendingLocation;pendingLocation=null;if(loc!=null && follow.isSelected() && !this.disposed)inspectLocation(loc);});
    private static ThreadPoolExecutor executor(String name,int threads){return new ThreadPoolExecutor(threads,threads,0,TimeUnit.MILLISECONDS,new ArrayBlockingQueue<>(64),r->{Thread t=new Thread(r,name);t.setDaemon(true);return t;});}
    private final ExecutorService searchWorker=executor("Janus Key search",1);

    private boolean changing,importing;
    private volatile boolean disposed;
    private volatile long revision;
    private Run displayedRun;
    private JPanel hoverDestination;
    private Inspection inspected;
    private long inspectedFunction;
    private long currentPage=1,totalPages;
    private volatile long timelineRequest;
    private boolean updatingPage;
    private final JSpinner pageNumber=new JSpinner(new SpinnerNumberModel(Long.valueOf(1),Long.valueOf(1),Long.valueOf(1),Long.valueOf(1)));
    private final JLabel pageTotal=new JLabel("of 0");
    private final JButton firstPage=button("First",()->loadPage(1)), earlierPage=button("Previous",()->loadPage(currentPage-1)), laterPage=button("Next",()->loadPage(currentPage+1)), lastPage=button("Last",()->loadPage(totalPages));
    private String mappingProblem;
    private static final int PAGE=300;
    record Bookmark(Run run,long sequence,long thread,long module,String note) {}
    private final List<TraceStore> stores=new ArrayList<>();

    static final class Run {
        final TraceStore store; final List<Module> modules; final List<Long> threads;
        long cursor,thread=-1,moduleId=-1;
        String category="All events",storage="";boolean writesOnly,following=true;int tab;Inspection inspection;long inspectionFunction;
        Run(TraceStore s,List<Row> m,List<Long> t) { store=s;modules=m.stream().map(Module::new).toList();threads=t;cursor=s.firstSequence; }
        @Override public String toString() { return store.label; }
    }
    record Module(Row row) {
        @Override public String toString() { String path=row.text("path"); return path.substring(Math.max(path.lastIndexOf('/'),path.lastIndexOf('\\'))+1)+" ["+row.text("module_id")+"]"; }
    }
    record Context(Run run,Module module,Program program,long imageBase,long cursor,long thread,long revision) {
        Long runtime(Address a) {
            if(a==null || !a.isMemoryAddress() || module==null || program==null) return null;
            long offset=a.getOffset()-imageBase;
            if(Long.compareUnsigned(offset,module.row.number("mapped_size"))>=0) return null;
            return module.row.number("base")+offset;
        }
        Address mapped(Row instruction) {
            if(program==null || module==null || instruction==null || instruction.number("module_id")!=module.row.number("module_id")) return null;
            try { return program.getImageBase().addNoWrap(instruction.number("module_offset")); } catch(Exception e) { return null; }
        }
    }
    TraceProvider(JanusKeyPlugin plugin,PluginTool tool) {
        super(tool,"Janus Key",plugin.getName()); this.plugin=plugin;
        searchPanel=new TraceSearchPanel(this);
        setDefaultWindowPosition(WindowPosition.BOTTOM);
        JPanel header=new JPanel(); header.setLayout(new BoxLayout(header,BoxLayout.Y_AXIS));
        JPanel first=line(); first.add(button("Import...",this::importRun)); first.add(new JLabel("Run")); first.add(runs); first.add(button("Unload",this::unload)); first.add(button("Cache...",this::cacheManagement)); first.add(button("Save session...",this::saveSession)); first.add(button("Open session...",this::openSession));
        JPanel second=line(); second.add(new JLabel("Module → current program")); second.add(modules); second.add(new JLabel("Thread")); second.add(threads); second.add(follow);
        JPanel third=line(); third.add(new JLabel("Moment #")); third.add(sequence); third.add(button("Set moment",this::setMoment)); third.add(button("Previous event",()->step(false))); third.add(button("Next event",()->step(true))); third.add(kind);
        header.add(first); header.add(second); header.add(mapping); header.add(third); panel.add(header,BorderLayout.NORTH);
        JPanel time=new JPanel(new BorderLayout()); time.add(new JScrollPane(timeline),BorderLayout.CENTER);time.add(timelineRange,BorderLayout.NORTH);
        JPanel paging=line();paging.add(firstPage);paging.add(earlierPage);paging.add(new JLabel("Page"));paging.add(pageNumber);paging.add(pageTotal);paging.add(button("Go",this::choosePage));paging.add(laterPage);paging.add(lastPage);paging.add(button("At moment",this::showMoment));
        pageNumber.setEditor(new JSpinner.NumberEditor(pageNumber,"0"));((JSpinner.DefaultEditor)pageNumber.getEditor()).getTextField().setColumns(7);
        pageNumber.setToolTipText("Enter a page number and press Enter or Go; pages contain up to 300 matching events.");
        pageNumber.addChangeListener(e->{if(!updatingPage)loadPage(((Number)pageNumber.getValue()).longValue());});
        ((JSpinner.DefaultEditor)pageNumber.getEditor()).getTextField().addActionListener(e->choosePage());
        JPanel navigation=line();navigation.add(button("Go to instruction",()->jumpSelected(timeline,timelineModel,false)));navigation.add(button("Go to function",()->jumpSelected(timeline,timelineModel,true)));navigation.add(button("Match call / return",this::matchCall));
        JPanel footer=new JPanel(new GridLayout(0,1));footer.add(paging);footer.add(navigation);time.add(footer,BorderLayout.SOUTH);updatePageControls(); tabs.addTab("Timeline",time);
        JPanel values=new JPanel(new BorderLayout(4,4)); JPanel search=line(); search.add(new JLabel("Storage")); search.add(watch); search.add(button("Inspect",this::inspectWatch)); search.add(writes); search.add(button("Go to writer",()->jumpSelected(history,historyModel,false))); search.add(button("Writer function",()->jumpSelected(history,historyModel,true)));search.add(button("Call / return",()->matchCall(selected(history,historyModel))));
        JPanel valuesTop=new JPanel(new BorderLayout()); valuesTop.add(search,BorderLayout.NORTH); valuesTop.add(historyTitle,BorderLayout.SOUTH); values.add(valuesTop,BorderLayout.NORTH); values.add(new JScrollPane(history),BorderLayout.CENTER); tabs.addTab("Value history",values);
        detail.setEditable(false); detail.setLineWrap(true); detail.setWrapStyleWord(true); tabs.addTab("Event details",new JScrollPane(detail));
        comparison.setEditable(false); comparison.setLineWrap(true); comparison.setWrapStyleWord(true); JPanel comparePanel=new JPanel(new BorderLayout()); comparePanel.add(new JScrollPane(comparison)); comparePanel.add(button("Compare current instruction across runs",this::compare),BorderLayout.SOUTH); tabs.addTab("Compare runs",comparePanel);
        JPanel frames=new JPanel(new BorderLayout());frames.add(new JLabel("Active recorded calls at this moment · select one thread · newest frame first"),BorderLayout.NORTH);frames.add(new JScrollPane(stack));JPanel frameActions=line();frameActions.add(button("Refresh call stack",this::refreshStack));frameActions.add(button("Go to caller",()->jumpSelected(stack,stackModel,false)));frameActions.add(button("Call / return",()->matchCall(selected(stack,stackModel))));frames.add(frameActions,BorderLayout.SOUTH);tabs.addTab("Call stack",frames);
        JPanel notes=new JPanel(new BorderLayout());notes.add(new JScrollPane(bookmarkList));JPanel noteActions=line();noteActions.add(button("Bookmark moment...",this::bookmark));noteActions.add(button("Go to bookmark",this::goBookmark));noteActions.add(button("Remove",()->{int i=bookmarkList.getSelectedIndex();if(i>=0){bookmarks.remove(i);bookmarkLabels.remove(i);}}));notes.add(noteActions,BorderLayout.SOUTH);tabs.addTab("Bookmarks",notes);
        JPanel hot=new JPanel(new BorderLayout());hot.add(new JLabel("Most executed instructions in the selected module · entire run · code revisions remain separate"),BorderLayout.NORTH);hot.add(new JScrollPane(coverageTable));JPanel hotActions=line();hotActions.add(button("Load hot spots",this::coverage));hotActions.add(button("Go to instruction",this::jumpCoverage));hot.add(hotActions,BorderLayout.SOUTH);tabs.addTab("Hot spots",hot);coverageTable.setAutoCreateRowSorter(true);coverageTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);coverageTable.addMouseListener(new MouseAdapter(){@Override public void mouseClicked(MouseEvent e){if(e.getClickCount()==2)jumpCoverage();}});
        tabs.addTab("Search",searchPanel);
        panel.add(tabs,BorderLayout.CENTER); panel.add(status,BorderLayout.SOUTH); panel.setBorder(BorderFactory.createEmptyBorder(6,6,6,6)); panel.setPreferredSize(new Dimension(1050,430));
        timeline.setAutoCreateRowSorter(true); history.setAutoCreateRowSorter(true); timeline.setSelectionMode(ListSelectionModel.SINGLE_SELECTION); history.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        wireTable(timeline,timelineModel); wireTable(history,historyModel);
        stack.setAutoCreateRowSorter(true);stack.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);wireTable(stack,stackModel);
        runs.addActionListener(e->{if(!changing) selectRun();}); modules.addActionListener(e->{if(!changing){Run r=active();Module m=(Module)modules.getSelectedItem();if(r!=null)r.moduleId=m==null?-1:m.row.number("module_id");invalidate();inspected=null;historyModel.set(List.of());coverageModel.set(List.of());comparison.setText("");updateMapping();refresh();}});
        threads.addActionListener(e->{if(!changing){Run r=active();if(r!=null)r.thread=threads.getSelectedIndex()<=0?-1:Long.parseLong((String)threads.getSelectedItem());resetTimelineFilter();}});
        kind.addActionListener(e->{if(!changing)resetTimelineFilter();}); writes.addActionListener(e->{Run r=active();if(r!=null)r.writesOnly=writes.isSelected();refreshHistory();}); follow.addActionListener(e->{Run r=active();if(r!=null)r.following=follow.isSelected();if(!follow.isSelected()){pendingLocation=null;followTimer.stop();}}); sequence.addActionListener(e->setMoment()); watch.addActionListener(e->inspectWatch());
        addToTool();
        followTimer.setRepeats(false);
        tabs.addChangeListener(e->{if(changing)return;if(tabs.getSelectedIndex()==1)refreshHistory();else cancelQuery("Loading value history");if(tabs.getSelectedIndex()==2)refreshDetails();else cancelQuery("Comparing write samples");if(tabs.getSelectedIndex()==4)refreshStack();else cancelQuery("Loading call stack");});
    }
    private static JPanel line() { return new JPanel(new FlowLayout(FlowLayout.LEFT,6,3)); }
    private static JButton button(String label,Runnable action) { JButton b=new JButton(label);b.addActionListener(e->action.run());return b; }
    @Override public JComponent getComponent() { return panel; }
    Run active() { return (Run)runs.getSelectedItem(); }
    Context context() { Run r=active(); Program p=plugin.getCurrentProgram();return r==null?null:new Context(r,mappingProblem==null?(Module)modules.getSelectedItem():null,p,p==null?0:p.getImageBase().getOffset(),r.cursor,r.thread,revision); }
    private void invalidate() { revision++;clearHover();for(QueryJob job:new ArrayList<>(jobs.values()))job.cancel();jobs.clear(); }
    private void clearHover() { JPanel destination=hoverDestination;hoverDestination=null;if(destination!=null){destination.removeAll();destination.revalidate();destination.repaint();} }
    interface Work<T> { T run(TraceStore store) throws Exception; }
    private final class QueryJob {
        final QueryControl control;final ProgressStatus.Activity activity;final ThreadPoolExecutor executor;
        volatile Future<?> future;volatile boolean running;
        QueryJob(String label,ThreadPoolExecutor executor){this.executor=executor;control=new QueryControl(java.time.Duration.ofSeconds(executor==worker?5:60));activity=status.begin(label,control::cancel);}
        void cancel(){control.cancel();if(!running && future instanceof Runnable task && executor.remove(task)){future.cancel(false);activity.close();}}
    }
    private void cancelQuery(String label){QueryJob old=jobs.remove(label);if(old!=null)old.cancel();}
    <T> void query(Context c,String label,Work<T> work,Consumer<T> done) {
        if(disposed || c==null)return;cancelQuery(label);
        ThreadPoolExecutor executor=(ThreadPoolExecutor)(label.equals("Loading hot spots") || label.equals("Comparing runs")?analysisWorker:worker);
        QueryJob job=new QueryJob(label,executor);jobs.put(label,job);long queued=System.nanoTime();
        try {job.future=executor.submit(()->{
            job.running=true;job.activity.start();long started=System.nanoTime();
            try(QueryControl.Scope scope=job.control.activate()) {
                QueryControl.check();
                try(TraceStore reader=c.run.store.openSearch()) {
                    T result=work.run(reader);
                    QueryControl.check();
                    SwingUtilities.invokeLater(()->{if(!disposed && !job.control.cancelled() && revision==c.revision && active()==c.run && jobs.get(label)==job)done.accept(result);});
                }
            } catch(Exception e) {SwingUtilities.invokeLater(()->{if(!disposed && revision==c.revision && jobs.get(label)==job && (!job.control.cancelled() || job.control.timedOut()))status.setText(label+": "+(job.control.timedOut()?"took too long; narrow the selection or try again.":e.getMessage()));});}
            finally {if(Boolean.getBoolean("janus.timings"))Msg.info(this,label+": queued "+((started-queued)/1_000_000)+" ms, running "+((System.nanoTime()-started)/1_000_000)+" ms");SwingUtilities.invokeLater(()->jobs.remove(label,job));job.activity.close();}
        });}catch(RejectedExecutionException e){jobs.remove(label,job);job.activity.close();if(!disposed)status.setText("Background queue is full; retry this action.");}
    }
    void importRun() {
        JFileChooser chooser=new JFileChooser(); chooser.setDialogTitle("Import Janus Key run — trace.jkt or CSV directory"); chooser.setFileSelectionMode(JFileChooser.FILES_AND_DIRECTORIES);
        if(chooser.showOpenDialog(panel)==JFileChooser.APPROVE_OPTION) importPaths(List.of(chooser.getSelectedFile().toPath()),null);
    }
    private void importPaths(List<Path> paths,Properties session) {
        if(importing){status.setText("An import is already running.");return;}
        if(session==null && paths.size()==1){Path path=paths.get(0).toAbsolutePath().normalize();for(Run run:searchRuns(true))if(sameSource(path,run.store)){runs.setSelectedItem(run);setVisible(true);status.setText("This recording is already loaded.");return;}}
        importing=true;setVisible(true);QueryControl control=new QueryControl();
        List<Run> ready=new ArrayList<>();
        boolean accepted=background(importWorker,"Preparing "+paths.size()+" run(s)",control::cancel,activity->{
            try(QueryControl.Scope scope=control.activate()) {
                for(int i=0;i<paths.size();i++) {
                    QueryControl.check();Path path=paths.get(i);activity.update("Opening "+path.getFileName());
                    TraceStore store=null;Run run;
                    try {store=TraceStore.openPrepared(path,(phase,n,total)->{QueryControl.check();activity.update(path.getFileName()+": "+phase,n,total);});run=new Run(store,store.modules(),store.threads());}
                    catch(Exception e){if(store!=null)try{store.close();}catch(Exception close){e.addSuppressed(close);}throw e;}
                    if(session!=null){run.cursor=Math.max(0,Math.min(store.lastSequence,parse(session.getProperty(i+".cursor"),run.cursor)));run.thread=parse(session.getProperty(i+".thread"),-1);if(!run.threads.contains(run.thread))run.thread=-1;run.moduleId=parse(session.getProperty(i+".module"),-1);run.category=session.getProperty(i+".category","All events");if(!java.util.Arrays.asList("All events","Writes","Calls / returns","Control flow","Memory lifetime","System / process","Capture diagnostics").contains(run.category))run.category="All events";run.storage=session.getProperty(i+".storage","");run.writesOnly=Boolean.parseBoolean(session.getProperty(i+".writes","false"));run.following=Boolean.parseBoolean(session.getProperty(i+".follow","true"));run.tab=(int)Math.max(0,Math.min(7,parse(session.getProperty(i+".tab"),0)));run.inspection=readInspection(session,i+".inspection.");if(run.inspection==null)run.inspection=inspectionFromStorage(run.storage);run.inspectionFunction=parse(session.getProperty(i+".inspectionFunction"),parse(session.getProperty(i+".inspection.function"),0));}
                    ready.add(run);boolean first=i==0;
                    SwingUtilities.invokeLater(()->{if(disposed){closeLater(run.store);return;}changing=true;stores.add(run.store);runs.addItem(run);if(first)runs.setSelectedItem(run);changing=false;if(first)selectRun();});
                }
                List<Run> completed=List.copyOf(ready);
                SwingUtilities.invokeLater(()->{if(disposed)return;if(session!=null){int n=(int)Math.min(10000,Math.max(0,parse(session.getProperty("bookmarks"),0)));for(int i=0;i<n;i++){String key="bookmark."+i+".";int index=(int)parse(session.getProperty(key+"run"),-1);if(index<0 || index>=completed.size())continue;Run run=completed.get(index);long seq=parse(session.getProperty(key+"sequence"),0);if(seq<0 || seq>run.store.lastSequence)continue;addBookmark(new Bookmark(run,seq,parse(session.getProperty(key+"thread"),-1),parse(session.getProperty(key+"module"),-1),session.getProperty(key+"note","")));}}status.setText("Prepared "+completed.size()+" run(s). Indexes are saved for reopening.");});
                try{TraceStore.pruneCache();}catch(IOException e){Msg.warn(this,"Could not prune old trace caches: "+e.getMessage());}
            }catch(Exception e){SwingUtilities.invokeLater(()->{if(!disposed)status.setText(control.cancelled()?"Preparation cancelled; completed runs remain available.":"Preparation stopped: "+e.getMessage());});}
            finally{SwingUtilities.invokeLater(()->importing=false);}
        },()->SwingUtilities.invokeLater(()->importing=false));
        if(!accepted)importing=false;
    }
    private static long parse(String s,long fallback) { try{return Long.parseLong(s);}catch(Exception e){return fallback;} }
    private static Inspection readInspection(Properties values,String prefix) {
        String kind=values.getProperty(prefix+"kind");if(kind==null)return null;
        try {
            Inspection.Kind parsed=Inspection.Kind.valueOf(kind);String label=values.getProperty(prefix+"label","");long address=parse(values.getProperty(prefix+"address"),0);int size=(int)Math.max(0,Math.min(256,parse(values.getProperty(prefix+"size"),0)));String register=values.getProperty(prefix+"register","");int byteOffset=(int)Math.max(0,Math.min(256,parse(values.getProperty(prefix+"byteOffset"),0)));String note=values.getProperty(prefix+"note","");
            return new Inspection(parsed,label,address,size,register,byteOffset,note);
        } catch(IllegalArgumentException e){return null;}
    }
    private static Inspection inspectionFromStorage(String storage) {
        if(storage==null)return null;String text=storage.trim();
        try {
            if(text.startsWith("0x") || text.startsWith("0X")){String[] parts=text.split(":",-1);if(parts.length>2)return null;long address=Long.parseUnsignedLong(parts[0].substring(2),16);int size=parts.length==1?8:Integer.parseInt(parts[1]);if(size<1 || size>256)return null;return Inspection.memory(text,address,size,"Restored explicit runtime address; heap/stack addresses are run-specific.");}
            if(text.matches("[A-Za-z][A-Za-z0-9]*"))return new Inspection(Inspection.Kind.REGISTER,text,0,8,text.toLowerCase(Locale.ROOT),0,"Restored captured register; select one thread.");
        } catch(NumberFormatException ignored){}
        return null;
    }
    private static void writeInspection(Properties values,String prefix,Inspection inspection,long function) {
        if(inspection==null)return;values.setProperty(prefix+"kind",inspection.kind().name());values.setProperty(prefix+"label",inspection.label());values.setProperty(prefix+"address",Long.toString(inspection.address()));values.setProperty(prefix+"size",Integer.toString(inspection.size()));values.setProperty(prefix+"register",inspection.register());values.setProperty(prefix+"byteOffset",Integer.toString(inspection.byteOffset()));values.setProperty(prefix+"note",inspection.note());values.setProperty(prefix+"function",Long.toString(function));
    }
    private static boolean sameSource(Path selected,TraceStore store) {
        Path path=selected.toAbsolutePath().normalize(), source=store.source.toAbsolutePath().normalize();
        return source.equals(path) || (source.getFileName()!=null && source.getFileName().toString().equalsIgnoreCase("trace.jkt") && source.getParent()!=null && source.getParent().equals(path));
    }
    private void rememberView(){if(displayedRun!=null){displayedRun.category=(String)kind.getSelectedItem();displayedRun.storage=watch.getText();displayedRun.writesOnly=writes.isSelected();displayedRun.following=follow.isSelected();displayedRun.tab=tabs.getSelectedIndex();displayedRun.inspection=inspected;displayedRun.inspectionFunction=inspectedFunction;}}
    private void selectRun() {
        pendingLocation=null;followTimer.stop();rememberView();invalidate();detailEvent=null;enrichedSequence=-1;timelineModel.set(List.of());stackModel.set(List.of());coverageModel.set(List.of());detail.setText("");comparison.setText("");changing=true;modules.removeAllItems();threads.removeAllItems();threads.addItem("All threads");Run r=active();
        if(r!=null) {
            runs.setToolTipText(r.store.source.toString());
            for(Module m:r.modules)modules.addItem(m);for(long t:r.threads)threads.addItem(Long.toString(t));
            modules.setSelectedIndex(-1);
            Module best=null;
            for(Module m:r.modules)if(m.row.number("module_id")==r.moduleId)best=m;
            if(best==null && plugin.getCurrentProgram()!=null) {
                String name=plugin.getCurrentProgram().getName();List<Module> matching=r.modules.stream().filter(m->basename(m.row.text("path")).equalsIgnoreCase(name)).toList();if(matching.size()==1)best=matching.get(0);
            }
            if(best!=null) {modules.setSelectedItem(best);r.moduleId=best.row.number("module_id");}
            threads.setSelectedItem(r.thread<0?"All threads":Long.toString(r.thread));sequence.setText(Long.toString(r.cursor));
            kind.setSelectedItem(r.category);watch.setText(r.storage);writes.setSelected(r.writesOnly);follow.setSelected(r.following);tabs.setSelectedIndex(r.tab);
        }
        changing=false;displayedRun=r;inspected=r==null?null:r.inspection;inspectedFunction=r==null?0:r.inspectionFunction;historyModel.set(List.of());updateMapping();refresh();
    }
    static String basename(String p) { return p.substring(Math.max(p.lastIndexOf('/'),p.lastIndexOf('\\'))+1); }
    private void updateMapping() {
        Module selected=(Module)modules.getSelectedItem();Program program=plugin.getCurrentProgram();
        mappingProblem=selected!=null && program!=null?ModuleIdentity.problem(program,selected.row):null;
        if(mappingProblem!=null){mapping.setText("Mapping unavailable: "+mappingProblem);return;}
        Context c=context();
        if(c==null || c.module==null || c.program==null) {mapping.setText("Select the recorded module corresponding to the open program to enable navigation and hovers.");return;}
        mapping.setText(c.module+" → "+c.program.getName()+" at "+c.program.getImageBase()+" · PE identity matched; instruction bytes checked before navigation");
    }
    void programChanged() { pendingLocation=null;followTimer.stop();invalidate(); historyModel.set(List.of()); if(!changing)selectRun(); }
    void locationChanged(ProgramLocation loc) { if(loc!=null && follow.isSelected() && active()!=null){pendingLocation=loc;followTimer.restart();} }
    void inspectLocation(ProgramLocation loc) {
        Context c=context();if(c==null || c.module==null || c.program!=loc.getProgram())return;
        Address a=loc.getRefAddress()!=null?loc.getRefAddress():loc.getAddress();if(c.runtime(a)==null)return;
        Function f=c.program.getFunctionManager().getFunctionAt(a);
        if(f!=null) inspect(new Inspection(Inspection.Kind.FUNCTION,f.getName(),c.runtime(a),0,"",0,"Observed Windows x64 argument and return channels."),0,false);
        else if(c.program.getListing().getDefinedDataContaining(a)!=null) {Data d=c.program.getListing().getDefinedDataContaining(a);inspect(Inspection.memory(d.getPathName(),c.runtime(a),(int)(d.getMaxAddress().subtract(a)+1),"Module-relative data storage."),0,false);}
        else inspect(new Inspection(Inspection.Kind.INSTRUCTION,a.toString(),a.getOffset()-c.imageBase,0,"",0,"Instruction observations at or before the selected moment."),0,false);
    }
    void inspect(Inspection target,long function,boolean show) { inspected=target;inspectedFunction=function;if(show){follow.setSelected(false);tabs.setSelectedIndex(1);setVisible(true);}refreshHistory(); }
    private void inspectWatch() {
        String s=watch.getText().trim();
        try {
            if(s.startsWith("0x")) {String[] parts=s.split(":",-1);long address=Long.parseUnsignedLong(parts[0].substring(2),16);int size=parts.length==1?8:Integer.parseInt(parts[1]);if(parts.length>2 || size<1 || size>256)throw new IllegalArgumentException();inspect(Inspection.memory(s,address,size,"Explicit runtime address; heap/stack addresses are run-specific."),0,true);}
            else if(s.matches("[A-Za-z][A-Za-z0-9]*")) inspect(new Inspection(Inspection.Kind.REGISTER,s,0,8,s.toLowerCase(Locale.ROOT),0,"Raw captured register; select one thread."),0,true);
            else throw new IllegalArgumentException();
        } catch(Exception e) {status.setText("Use a register name (rax) or runtime address and byte size (0x1234:8, 1–256 bytes).");}
    }
    Inspection resolveStack(TraceStore store,Context c,Inspection target,long function) throws Exception {
        if(!target.register().equals("stack"))return target;
        if(c.thread<0 || function==0)return Inspection.unknown(target.label(),"Select a thread and a function with a recorded active call to resolve stack storage.");
        for(var call:store.activeCalls(c.thread,c.cursor,256)) {
            Row r=call.row();
            if(r.number("target_address")!=function)continue;
            return Inspection.memory(target.label(),r.number("stack_pointer")-8+target.address(),target.size(),"Stack storage from call #"+r.text("call_id")+"; Windows x64 entry RSP + Ghidra stack offset.");
        }
        return Inspection.unknown(target.label(),"No active recorded call frame (scope filtering, missing call or incomplete trace).");
    }
    private List<TraceStore.Event> history(TraceStore s,Context c,Inspection target,boolean onlyWrites,int limit) throws Exception {
        return switch(target.kind()) {
            case MEMORY->s.historyMemory(target.address(),target.size(),c.cursor,onlyWrites,limit);
            case REGISTER->s.historyRegister(target.register(),c.thread,c.cursor,onlyWrites,limit);
            case FUNCTION->s.calls(target.address(),c.thread,c.cursor,limit);
            case INSTRUCTION->c.module==null?List.of():s.at(c.module.row.number("module_id"),target.address(),c.thread,c.cursor,limit);
            default->List.of();
        };
    }
    private void refreshHistory() {
        Context c=context();Inspection target=inspected;long function=inspectedFunction;boolean onlyWrites=writes.isSelected();if(c==null || target==null || tabs.getSelectedIndex()!=1)return;
        query(c,"Loading value history",store->{Inspection resolved=resolveStack(store,c,target,function);return new HistoryResult(resolved,history(store,c,resolved,onlyWrites,PAGE));},r->{
            if(inspected!=target)return;historyModel.set(r.events);historyTitle.setText(r.target.label()+" · "+r.target.note()+" · newest "+r.events.size()+" observations ≤ #"+c.cursor);});
    }
    record HistoryResult(Inspection target,List<TraceStore.Event> events) {}
    void hover(Context c,Inspection target,long function,JPanel destination) {
        if(hoverDestination!=null && hoverDestination!=destination)cancelQuery("Loading hover evidence");
        hoverDestination=destination;
        destination.addHierarchyListener(e->{if((e.getChangeFlags()&HierarchyEvent.SHOWING_CHANGED)!=0 && !destination.isShowing() && hoverDestination==destination){hoverDestination=null;cancelQuery("Loading hover evidence");}});
        query(c,"Loading hover evidence",store->{Inspection resolved=resolveStack(store,c,target,function);List<TraceStore.Event> rows=history(store,c,resolved,false,256);Map<Long,Row> returns=new HashMap<>();if(resolved.kind()==Inspection.Kind.FUNCTION)for(var e:rows.stream().limit(3).toList()){Row r=store.returned(e.row().number("call_id"),e.row().number("thread_id"),c.cursor);if(r!=null)returns.put(e.sequence(),r);}return new HoverResult(resolved,rows,returns);},result->{
            if(hoverDestination!=destination)return;
            destination.removeAll();Inspection resolved=result.target;List<TraceStore.Event> rows=result.events;
            StringBuilder text=new StringBuilder("<html><div style='width:390px'><b>"+Inspection.escape(target.label())+"</b><br>"+Inspection.escape(c.run.toString())+" · "+(c.thread<0?"all threads":"thread "+c.thread)+" · at #"+c.cursor+"<br>");
            if(resolved.kind()==Inspection.Kind.MEMORY || resolved.kind()==Inspection.Kind.REGISTER) {
                ValueEvidence value=resolved.kind()==Inspection.Kind.MEMORY?ValueEvidence.memory(resolved.address(),resolved.size(),rows):ValueEvidence.register(resolved.byteOffset(),resolved.size(),rows);
                text.append("<br><b>").append(value.hex()).append("</b><br>").append(value.interpretation()).append("<br>");
                if(value.beforeWrite)text.append("Before-write observation; resulting value is not yet captured.<br>");
                text.append("Last observed storage, not a guarantee of unchanged state.<br>");
                for(var source:value.sources.stream().limit(3).toList())text.append("#").append(source.sequence()).append(" · ").append(Inspection.escape(source.row().text("access"))).append(" · ").append(Inspection.escape(source.routine())).append("<br>");
            } else if(resolved.kind()==Inspection.Kind.FUNCTION) {
                text.append("<br>Recent calls (raw Windows x64 channels):<br>");
                for(var event:rows.stream().limit(3).toList()) {Row r=event.row();text.append("#").append(event.sequence()).append(" · RCX ").append(r.text("rcx")).append(" · RDX ").append(r.text("rdx")).append("<br>R8 ").append(r.text("r8")).append(" · R9 ").append(r.text("r9"));Row ret=result.returns.get(event.sequence());if(ret!=null)text.append(" → RAX ").append(ret.text("integer_return_low")).append(" (return #").append(ret.text("sequence")).append(", ").append(ret.number("monotonic_ns")-r.number("monotonic_ns")).append(" ns)");else text.append(" → no return observed by this moment");text.append("<br>");}
            } else for(var event:rows.stream().limit(3).toList()) text.append("#").append(event.sequence()).append(" ").append(Inspection.escape(TraceReader.FILES[event.row().type])).append(" ").append(Inspection.escape(event.row().text("value_hex"))).append("<br>");
            if(rows.isEmpty())text.append("No observation for this selection.<br>");
            text.append("Newest ").append(rows.size()).append(" matching observations examined (maximum 256).<br>");
            text.append("<br>").append(Inspection.escape(resolved.note())).append("</div></html>");JLabel label=new JLabel(text.toString());label.setVerticalAlignment(SwingConstants.TOP);JScrollPane content=new JScrollPane(label);content.setBorder(BorderFactory.createEmptyBorder());destination.add(content,BorderLayout.CENTER);
            JPanel actions=line();actions.add(button("History",()->inspect(target,function,true)));
            rows.stream().filter(e->e.row().text("access").equals("write_after") || e.row().text("access").equals("write_before")).findFirst().ifPresent(e->actions.add(button("Last writer",()->jump(c,e,false))));
            destination.add(actions,BorderLayout.SOUTH);destination.revalidate();destination.repaint();
        });
    }
    record HoverResult(Inspection target,List<TraceStore.Event> events,Map<Long,Row> returns) {}
    private void setMoment() {
        Run r=active();if(r==null)return;
        try {long n=Long.parseLong(sequence.getText().trim());if(n<0 || n>r.store.lastSequence)throw new IllegalArgumentException();r.cursor=n;invalidate();refresh();}
        catch(Exception e){sequence.setText(Long.toString(r.cursor));status.setText("Moment must be between 0 and "+r.store.lastSequence);}
    }
    private void step(boolean forward) {
        Context c=context();if(c==null)return;String filter=(String)kind.getSelectedItem();
        query(c,"Finding adjacent event",store->store.timeline(c.cursor+(forward?1:0),c.thread,filter,forward,1),events->{if(!events.isEmpty()){c.run.cursor=events.get(0).sequence();sequence.setText(Long.toString(c.run.cursor));invalidate();refresh();}});
    }
    private void refresh() {showMoment();refreshHistory();refreshStack();Run r=active();status.setText(r==null?"Import a run to explore recorded execution.":summary(r));}
    private void refreshStack() {Context c=context();if(c==null || c.thread<0 || tabs.getSelectedIndex()!=4){stackModel.set(List.of());return;}query(c,"Loading call stack",store->store.activeCalls(c.thread,c.cursor,PAGE),stackModel::set);}
    private static String summary(Run r) {return r.store.label+" | "+r.store.count+" records | moment #"+r.cursor+" | "+(r.store.incomplete || !r.store.finished?"INCOMPLETE RUN - observations may be missing":"clean run finish recorded")+" | "+r.store.captureDiagnostics+" capture notices | "+r.store.missingSequences+" missing sequence IDs | select row: set moment; double-click / Enter: navigate";}
    private void choosePage() {
        try {updatingPage=true;pageNumber.commitEdit();}
        catch(java.text.ParseException e){status.setText("Enter a page number between 1 and "+totalPages);return;}
        finally {updatingPage=false;}
        loadPage(((Number)pageNumber.getValue()).longValue());
    }
    private void updatePageControls() {
        updatingPage=true;
        long maximum=Math.max(1,totalPages);currentPage=Math.max(1,Math.min(currentPage,maximum));
        SpinnerNumberModel model=(SpinnerNumberModel)pageNumber.getModel();model.setMinimum(Long.valueOf(1));model.setMaximum(Long.valueOf(maximum));model.setStepSize(Long.valueOf(1));model.setValue(Long.valueOf(currentPage));
        JFormattedTextField editor=((JSpinner.DefaultEditor)pageNumber.getEditor()).getTextField();editor.setValue(Long.valueOf(currentPage));editor.setText(Long.toString(currentPage));
        updatingPage=false;pageTotal.setText("of "+totalPages);pageNumber.setEnabled(totalPages>0);
        firstPage.setEnabled(currentPage>1);earlierPage.setEnabled(currentPage>1);laterPage.setEnabled(currentPage<totalPages);lastPage.setEnabled(currentPage<totalPages);
    }
    private void resetTimelineFilter() {
        invalidate();currentPage=1;totalPages=0;updatePageControls();
        timeline.clearSelection();timelineModel.set(List.of());detail.setText("");historyModel.set(List.of());stackModel.set(List.of());
        if(timeline.getRowSorter()!=null)timeline.getRowSorter().setSortKeys(List.of());
        Run r=active();if(r!=null)r.category=(String)kind.getSelectedItem();
        detailEvent=null;enrichedSequence=-1;loadTimeline(0,true);
    }
    private void showMoment() {loadTimeline(0);}
    private void loadPage(long page) {loadTimeline(Math.max(1,page));}
    private void loadTimeline(long requested) {loadTimeline(requested,false);}
    private void loadTimeline(long requested,boolean resetMoment) {
        Context c=context();long request=++timelineRequest;
        if(c==null){timelineModel.set(List.of());currentPage=1;totalPages=0;updatePageControls();timelineRange.setText("Import a run to browse its recorded events.");return;}
        String filter=(String)kind.getSelectedItem();
        query(c,"Loading timeline",store->requested==0?store.timelineAtMoment(c.cursor,c.thread,filter,PAGE):store.numberedTimeline(requested,c.thread,filter,PAGE),result->{
            if(request!=timelineRequest)return;
            currentPage=result.page();totalPages=result.pages();updatePageControls();updatingSelection=true;
            try{timeline.clearSelection();timelineModel.set(result.events());
                if(resetMoment && !result.events().isEmpty())timeline.setRowSelectionInterval(0,0);
                if(requested==0)for(int i=0;i<result.events().size();i++)if(result.events().get(i).sequence()==c.cursor){int view=timeline.convertRowIndexToView(i);timeline.setRowSelectionInterval(view,view);break;}
            }finally{updatingSelection=false;}
            if(resetMoment && !result.events().isEmpty()){TraceStore.Event nearest=result.events().stream().filter(e->e.sequence()>=c.cursor).findFirst().orElse(result.events().get(result.events().size()-1));updatingSelection=true;try{timeline.setRowSelectionInterval(timeline.convertRowIndexToView(result.events().indexOf(nearest)),timeline.convertRowIndexToView(result.events().indexOf(nearest)));}finally{updatingSelection=false;}selectEvent(nearest);}
            if(timeline.getRowCount()>0)timeline.scrollRectToVisible(timeline.getCellRect(Math.max(0,timeline.getSelectedRow()),0,true));
            var rows=result.events();timelineRange.setText(rows.isEmpty()?"No events match these filters. Try All events or All threads.":"Showing events "+((currentPage-1)*PAGE+1)+"-"+((currentPage-1)*PAGE+rows.size())+" of "+result.total()+" | #"+rows.get(0).sequence()+" to #"+rows.get(rows.size()-1).sequence());
        });
    }
    private void wireTable(GTable table,EventModel model) {
        table.getSelectionModel().addListSelectionListener(e->{if(!updatingSelection && !e.getValueIsAdjusting()){var selected=selected(table,model);if(selected!=null)selectEvent(selected);}});
        table.addMouseListener(new MouseAdapter(){@Override public void mouseClicked(MouseEvent e){if(e.getClickCount()==2)jumpSelected(table,model,false);}});
        table.getInputMap().put(KeyStroke.getKeyStroke(KeyEvent.VK_ENTER,0),"janus-go");table.getActionMap().put("janus-go",new AbstractAction(){@Override public void actionPerformed(ActionEvent e){jumpSelected(table,model,false);}});
    }
    private static TraceStore.Event selected(GTable table,EventModel model) {int row=table.getSelectedRow();return row<0?null:model.events.get(table.convertRowIndexToModel(row));}
    private void selectEvent(TraceStore.Event e) {
        Run r=active();if(r==null)return;r.cursor=e.sequence();sequence.setText(Long.toString(r.cursor));invalidate();
        detail.setText(TraceReader.FILES[e.row().type]+"\n\n"+e.row().describe()+"\nInstruction definition\n"+(e.instruction()==null?"Not present / not instruction-associated":e.instruction().describe()));detail.setCaretPosition(0);status.setText(summary(r));
        detailEvent=e;enrichedSequence=-1;refreshDetails();
        refreshHistory();refreshStack();
    }
    private void refreshDetails(){TraceStore.Event e=detailEvent;Context c=context();if(c==null || e==null || tabs.getSelectedIndex()!=2 || enrichedSequence==e.sequence() || !e.row().text("access").equals("write_after"))return;query(c,"Comparing write samples",store->store.transition(e),text->{if(detailEvent==e){enrichedSequence=e.sequence();if(!text.isEmpty())detail.append("\nWrite transition\n"+text);}});}
    private void jumpSelected(GTable table,EventModel model,boolean function) {var e=selected(table,model);Context c=context();if(e!=null && c!=null)jump(c,e,function);}
    void jump(Context c,TraceStore.Event event,boolean function) {
        if(plugin.getCurrentProgram()!=c.program){status.setText("The mapped program is no longer active.");return;}
        Address a=c.mapped(event.instruction());if(a==null){status.setText("This instruction belongs to another module or generated code. Open its program and select its module.");return;}
        try {
            byte[] expected=event.instruction().bytes("encoding_hex"), actual=new byte[expected.length];
            if(expected.length==0 || c.program.getMemory().getBytes(a,actual)!=expected.length || !Arrays.equals(expected,actual)) {status.setText("Code bytes differ at "+a+". This may be another build or a recorded code revision; navigation was withheld.");return;}
            if(function){Function f=c.program.getFunctionManager().getFunctionContaining(a);if(f==null){status.setText("Ghidra has no function at this instruction.");return;}a=f.getEntryPoint();}
            plugin.navigate(a);
        } catch(Exception e){status.setText("Cannot map recorded instruction: "+e.getMessage());}
    }
    private void matchCall() {matchCall(selected(timeline,timelineModel));}
    private void matchCall(TraceStore.Event e) {
        Context c=context();if(e==null || c==null)return;long call=e.row().number("call_id");if(call==0){status.setText("Select a matched call or return.");return;}
        query(c,"Matching call and return",store->store.events("e.kind IN(7,8) AND e.cid=? ORDER BY e.seq",3,call),rows->{detail.setText(rows.stream().map(v->TraceReader.FILES[v.row().type]+"\n"+v.row().describe()).reduce("",(a,b)->a+b+"\n"));tabs.setSelectedIndex(2);});
    }
    private void bookmark() {Context c=context();if(c==null)return;String note=JOptionPane.showInputDialog(panel,"Note for "+c.run+" at #"+c.cursor,"Bookmark moment",JOptionPane.PLAIN_MESSAGE);if(note==null)return;Bookmark b=new Bookmark(c.run,c.cursor,c.thread,c.module==null?-1:c.module.row.number("module_id"),note);addBookmark(b);}
    private void addBookmark(Bookmark b){bookmarks.add(b);bookmarkLabels.addElement(b.run+" · #"+b.sequence+" · "+b.note);}
    private void goBookmark(){int i=bookmarkList.getSelectedIndex();if(i<0)return;Bookmark b=bookmarks.get(i);if(!stores.contains(b.run.store)){status.setText("This bookmark's run was unloaded.");return;}b.run.cursor=b.sequence;b.run.thread=b.thread;b.run.moduleId=b.module;changing=true;runs.setSelectedItem(b.run);changing=false;selectRun();tabs.setSelectedIndex(0);}
    private void compare() {
        Context c=context();ProgramLocation loc=plugin.getProgramLocation();if(c==null || c.module==null || loc==null || c.runtime(loc.getAddress())==null)return;
        long offset=loc.getAddress().getOffset()-c.imageBase;List<Run> snapshot=new ArrayList<>();for(int i=0;i<runs.getItemCount();i++)snapshot.add(runs.getItemAt(i));
        query(c,"Comparing runs",store->{
            StringBuilder b=new StringBuilder("Instruction RVA "+Row.hex(offset)+"\nCounts cover each entire run; thread IDs are local to each run.\n\n");
            Row identity=c.module.row;
            for(Run r:snapshot) {
                List<Module> matches=r.modules.stream().filter(m->sameImage(identity,m.row)).toList();
                if(matches.size()!=1){b.append(r).append(": ambiguous or incompatible module identity; no comparison\n\n");continue;}
                try(TraceStore other=r.store.openSearch()){
                long id=matches.get(0).row.number("module_id");long n=other.executionCount(id,offset,-1);
                b.append(r).append(": ").append(n).append(" executions").append(r.store.finished?"":" (incomplete)").append('\n');
                for(var event:other.at(id,offset,-1,r.store.lastSequence,8))b.append("  #").append(event.sequence()).append(" ").append(TraceReader.FILES[event.row().type]).append(" ").append(event.row().text("value_hex")).append('\n');b.append('\n');}
            }
            return b.toString();
        },text->{comparison.setText(text);comparison.setCaretPosition(0);tabs.setSelectedIndex(3);});
    }
    private void coverage(){Context c=context();if(c==null || c.module==null)return;query(c,"Loading hot spots",store->store.coverage(c.module.row.number("module_id"),PAGE),coverageModel::set);}
    private void jumpCoverage(){int selected=coverageTable.getSelectedRow();Context c=context();if(selected<0 || c==null)return;Row definition=coverageModel.rows.get(coverageTable.convertRowIndexToModel(selected)).sample();jump(c,new TraceStore.Event(new Row(4),definition),false);}
    static boolean sameImage(Row a,Row b) {
        if(!a.flag("pe_identity_valid") || !b.flag("pe_identity_valid"))return false;
        for(String key:List.of("machine","pe_timestamp","pe_checksum","declared_image_size","entry_point_rva"))if(!a.text(key).equals(b.text(key)))return false;
        return basename(a.text("path")).equalsIgnoreCase(basename(b.text("path")));
    }
    private void cacheManagement() {
        List<TraceStore> open=List.copyOf(stores);
        background(lifecycleWorker,"Inspecting trace cache",null,activity->{
            Path root=TraceStore.cacheRoot();long total;try{total=TraceStore.cacheBytes();}catch(IOException e){status.setText("Could not inspect trace cache: "+e.getMessage());return;}long quota=TraceStore.cacheQuotaBytes();StringBuilder text=new StringBuilder("Prepared trace indexes are disposable and can be rebuilt from the original recording.\n\nCache location:\n").append(root).append("\nCache size: ").append(formatBytes(total)).append(" of ").append(formatBytes(quota)).append(" quota\n\n");
            if(open.isEmpty())text.append("No recordings are open.\n");else {text.append("Open recordings:\n");for(TraceStore store:open)text.append("• ").append(store.label).append(" — ").append(formatBytes(directorySize(store.cacheDirectory()))).append("\n  ").append(store.cacheDirectory()).append("\n");}
            SwingUtilities.invokeLater(()->{
                if(disposed)return;
                Object[] options={"Clear unused caches","Close"};int choice=JOptionPane.showOptionDialog(panel,text,"Janus Key cache",JOptionPane.DEFAULT_OPTION,JOptionPane.INFORMATION_MESSAGE,null,options,options[0]);
                if(choice==0)background(lifecycleWorker,"Clearing unused caches",null,ignored->{try{TraceStore.clearUnusedCache();status.setText("Unused trace caches cleared under "+TraceStore.cacheRoot());}catch(Exception e){status.setText("Cache cleanup failed: "+e.getMessage());}});
            });
        });
    }
    private static long directorySize(Path directory) {
        if(directory==null || !Files.isDirectory(directory))return 0;
        try(var files=Files.walk(directory)){return files.filter(Files::isRegularFile).mapToLong(path->{try{return Files.size(path);}catch(IOException e){return 0;}}).sum();}catch(IOException e){return 0;}
    }
    private static String formatBytes(long bytes) {
        if(bytes<1024)return bytes+" B";if(bytes<1024*1024)return String.format(Locale.ROOT,"%.1f KiB",bytes/1024.0);if(bytes<1024L*1024*1024)return String.format(Locale.ROOT,"%.1f MiB",bytes/(1024.0*1024));return String.format(Locale.ROOT,"%.2f GiB",bytes/(1024.0*1024*1024));
    }
    private void saveSession() {
        if(active()==null)return;rememberView();JFileChooser chooser=new JFileChooser();chooser.setSelectedFile(new File("janus.jksession"));if(chooser.showSaveDialog(panel)!=JFileChooser.APPROVE_OPTION)return;
        Properties p=new Properties();p.setProperty("version","1");p.setProperty("count",Integer.toString(runs.getItemCount()));
        for(int i=0;i<runs.getItemCount();i++){Run r=runs.getItemAt(i);p.setProperty(i+".path",r.store.source.toString());p.setProperty(i+".cursor",Long.toString(r.cursor));p.setProperty(i+".thread",Long.toString(r.thread));p.setProperty(i+".module",Long.toString(r.moduleId));p.setProperty(i+".category",r.category);p.setProperty(i+".storage",r.storage);p.setProperty(i+".writes",Boolean.toString(r.writesOnly));p.setProperty(i+".follow",Boolean.toString(r.following));p.setProperty(i+".tab",Integer.toString(r.tab));p.setProperty(i+".inspectionFunction",Long.toString(r.inspectionFunction));writeInspection(p,i+".inspection.",r.inspection,r.inspectionFunction);}
        int saved=0;for(Bookmark b:bookmarks){int index=-1;for(int i=0;i<runs.getItemCount();i++)if(runs.getItemAt(i)==b.run)index=i;if(index<0)continue;String key="bookmark."+saved+++".";p.setProperty(key+"run",Integer.toString(index));p.setProperty(key+"sequence",Long.toString(b.sequence));p.setProperty(key+"thread",Long.toString(b.thread));p.setProperty(key+"module",Long.toString(b.module));p.setProperty(key+"note",b.note);}p.setProperty("bookmarks",Integer.toString(saved));
        Path destination=chooser.getSelectedFile().toPath();
        background(lifecycleWorker,"Saving session",null,activity->{try(OutputStream out=Files.newOutputStream(destination)){p.store(out,"Janus Key session");status.setText("Session saved.");}catch(Exception e){status.setText("Save failed: "+e.getMessage());}});
    }

    private void openSession() {
        JFileChooser chooser=new JFileChooser();if(chooser.showOpenDialog(panel)!=JFileChooser.APPROVE_OPTION)return;
        Path source=chooser.getSelectedFile().toPath();
        background(lifecycleWorker,"Opening session",null,activity->{
            try(InputStream in=Files.newInputStream(source)){
                Properties p=new Properties();p.load(in);if(!p.getProperty("version","").equals("1"))throw new IOException("Unsupported session");
                int n=Integer.parseInt(p.getProperty("count"));if(n<1 || n>128)throw new IOException("Invalid run count");List<Path> paths=new ArrayList<>();for(int i=0;i<n;i++)paths.add(Path.of(p.getProperty(i+".path")));
                SwingUtilities.invokeLater(()->{if(!disposed){if(importing){status.setText("Finish the current import before opening a session.");return;}replaceLoadedRuns();importPaths(paths,p);}});
            }catch(Exception e){status.setText("Open session failed: "+e.getMessage());}
        });
    }
    private void replaceLoadedRuns() {
        pendingLocation=null;followTimer.stop();invalidate();List<Run> old=searchRuns(true);changing=true;for(Run run:old){searchPanel.runUnloaded(run);runs.removeItem(run);stores.remove(run.store);closeLater(run.store);}changing=false;displayedRun=null;bookmarks.clear();bookmarkLabels.clear();timelineModel.set(List.of());historyModel.set(List.of());stackModel.set(List.of());coverageModel.set(List.of());detail.setText("");comparison.setText("");
    }

    List<Run> searchRuns(boolean all) {List<Run> result=new ArrayList<>();if(all){for(int i=0;i<runs.getItemCount();i++)result.add(runs.getItemAt(i));}else if(active()!=null)result.add(active());return result;}
    boolean searchRunAvailable(Run run){return stores.contains(run.store) || searchRuns(true).contains(run);}
    void reportStatus(String message){status.setText(message);}
    Runnable searchBackground(String label,Runnable cancel,Consumer<ProgressStatus.Activity> work){return searchBackground(label,cancel,work,null);}
    Runnable searchBackground(String label,Runnable cancel,Consumer<ProgressStatus.Activity> work,Runnable cancelledBeforeStart){Runnable job=submitBackground(searchWorker,label,cancel,work,cancelledBeforeStart);return job==null?()->{}:job;}
    boolean background(String label,Runnable cancel,Consumer<ProgressStatus.Activity> work){return submitBackground(worker,label,cancel,work,null)!=null;}
    private boolean background(ExecutorService executor,String label,Runnable cancel,Consumer<ProgressStatus.Activity> work){return background(executor,label,cancel,work,null);}
    private boolean background(ExecutorService executor,String label,Runnable cancel,Consumer<ProgressStatus.Activity> work,Runnable cancelledBeforeStart){return submitBackground(executor,label,cancel,work,cancelledBeforeStart)!=null;}
    private Runnable submitBackground(ExecutorService executor,String label,Runnable cancel,Consumer<ProgressStatus.Activity> work,Runnable cancelledBeforeStart) {
        if(disposed)return null;
        AtomicBoolean requested=new AtomicBoolean(),completionDelivered=new AtomicBoolean();AtomicReference<Future<?>> submitted=new AtomicReference<>();ProgressStatus.Activity[] activityRef=new ProgressStatus.Activity[1];
        Runnable deliverCancelled=()->{if(cancelledBeforeStart!=null && completionDelivered.compareAndSet(false,true))SwingUtilities.invokeLater(cancelledBeforeStart);};
        Runnable requestCancel=()->{
            requested.set(true);if(cancel!=null)cancel.run();Future<?> future=submitted.get();
            if(future instanceof Runnable task && executor instanceof ThreadPoolExecutor pool && pool.remove(task)){future.cancel(false);deliverCancelled.run();ProgressStatus.Activity activity=activityRef[0];if(activity!=null)activity.close();}
        };
        ProgressStatus.Activity activity=status.begin(label,cancel==null?null:requestCancel);activityRef[0]=activity;
        try {
            Future<?> future=executor.submit(()->{
                if(requested.get()){deliverCancelled.run();activity.close();return;}
                activity.start();
                try{work.accept(activity);}
                catch(Exception e){if(!requested.get() && !disposed)status.setText(label+" failed: "+e.getMessage());}
                finally{activity.close();}
            });
            submitted.set(future);
            if(requested.get() && future instanceof Runnable task && executor instanceof ThreadPoolExecutor pool && pool.remove(task)){future.cancel(false);deliverCancelled.run();activity.close();}
            return cancel==null?()->{}:activity::requestCancel;
        } catch(RejectedExecutionException e){deliverCancelled.run();activity.close();if(!disposed)status.setText("Background queue is full; retry this action.");return null;}
    }
    void openSearchHit(Run run,TraceStore.Event event,boolean navigate,boolean function) {
        if(event==null || !searchRunAvailable(run)){status.setText("This search result's run is no longer loaded.");return;}
        run.cursor=event.sequence();run.thread=event.row().number("thread_id");
        if(event.instruction()!=null)run.moduleId=event.instruction().number("module_id");
        rememberView();displayedRun=null;run.category="All events";run.tab=0;changing=true;runs.setSelectedItem(run);changing=false;selectRun();selectEvent(event);tabs.setSelectedIndex(0);
        if(navigate)jump(context(),event,function);
    }
    private void unload() {Run r=active();if(r==null)return;pendingLocation=null;followTimer.stop();invalidate();searchPanel.runUnloaded(r);runs.removeItem(r);stores.remove(r.store);closeLater(r.store);}
    private void closeLater(TraceStore s) {try{lifecycleWorker.submit(()->{try{s.close();}catch(Exception e){Msg.error(this,"Cannot close Janus index",e);}});}catch(RejectedExecutionException e){CompletableFuture.runAsync(()->{try{s.close();}catch(Exception failure){Msg.error(this,"Cannot close Janus index",failure);}});}}
    void dispose() {disposed=true;pendingLocation=null;followTimer.stop();status.dispose();searchPanel.dispose();invalidate();for(TraceStore s:stores)closeLater(s);worker.shutdown();searchWorker.shutdown();importWorker.shutdown();analysisWorker.shutdown();lifecycleWorker.shutdown();removeFromTool();}

    private static final class EventModel extends AbstractTableModel {
        private List<TraceStore.Event> events=List.of();
        private final String[] columns={"Sequence","Thread","Event","Access / outcome","Function / caller","Instruction","Storage / target","Captured value"};
        void set(List<TraceStore.Event> e){events=List.copyOf(e);fireTableDataChanged();}
        @Override public int getRowCount(){return events.size();}
        @Override public int getColumnCount(){return columns.length;}
        @Override public String getColumnName(int c){return columns[c];}
        @Override public Class<?> getColumnClass(int c){return c<2?Long.class:String.class;}
        @Override public Object getValueAt(int index,int col){var e=events.get(index);Row r=e.row();return switch(col){case 0->e.sequence();case 1->r.number("thread_id");case 2->TraceReader.FILES[r.type].replace("_events","").replace('_',' ');case 3->r.type==18?r.text("reason").replace('_',' '):outcome(r);case 4->e.routine();case 5->e.code();case 6->r.type==6?r.text("register_name"):r.type==5?r.text("memory_address"):r.text("target_address");case 7->r.type==8?"RAX "+r.text("integer_return_low"):r.type==7?"RCX "+r.text("rcx")+", RDX "+r.text("rdx"):r.text("value_hex");default->"";};}
        private static String outcome(Row r){if(r.type==7)return "call #"+r.text("call_id");if(r.type==8)return r.flag("matched")?"return #"+r.text("call_id"):"unmatched return";if(r.containsKey("taken"))return r.flag("taken")?"taken":"not taken";return (r.text("access")+r.text("event")+(r.containsKey("action")?" · "+r.text("action"):"")).replace('_',' ');}
    }
    private static final class EvidenceTable extends GTable {
        EvidenceTable(EventModel model){super(model);setToolTipText("Select a row to inspect this observation.");}
        @Override public String getToolTipText(MouseEvent event){int row=rowAtPoint(event.getPoint()),column=columnAtPoint(event.getPoint());if(row<0 || column<0)return null;Object value=getValueAt(row,column);return "<html><div style='width:400px'>"+Inspection.escape(String.valueOf(value))+"</div></html>";}
    }
    private static final class CoverageModel extends AbstractTableModel {
        private List<TraceStore.Coverage> rows=List.of();
        private final String[] columns={"Executions","Function","Instruction RVA","Instruction","Code revision ID"};
        void set(List<TraceStore.Coverage> result){rows=List.copyOf(result);fireTableDataChanged();}
        @Override public int getRowCount(){return rows.size();}
        @Override public int getColumnCount(){return columns.length;}
        @Override public String getColumnName(int c){return columns[c];}
        @Override public Class<?> getColumnClass(int c){return c==0 || c==4?Long.class:String.class;}
        @Override public Object getValueAt(int row,int col){var r=rows.get(row);return switch(col){case 0->r.executions();case 1->r.routine();case 2->r.sample().text("module_offset");case 3->r.sample().text("disassembly");default->r.sample().number("instruction_id");};}
    }
}

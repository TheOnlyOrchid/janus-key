package janus.ghidra;

import janus.trace.*;
import docking.widgets.table.GTable;
import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.awt.event.*;
import java.util.List;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;

final class TraceSearchPanel extends JPanel {
    private final TraceProvider provider;
    private final JComboBox<String> mode=new JComboBox<>(new String[]{"Captured value","Value later becomes","Event details"});
    private final JComboBox<String> encoding=new JComboBox<>(new String[]{"Text: UTF-8 + UTF-16LE","Text: UTF-8","Text: UTF-16LE","Hex bytes (?? wildcard)","Unsigned 32-bit LE","Unsigned 64-bit LE"});
    private final JTextField find=new JTextField(16),then=new JTextField(16);
    private final JCheckBox allRuns=new JCheckBox("All imported runs"),matchCase=new JCheckBox("Match case",true),onlyWrites=new JCheckBox("Writes only"),advanced=new JCheckBox("More filters");
    private final JTextField thread=new JTextField(7),start=new JTextField(10),end=new JTextField(10),addressStart=new JTextField(12),addressEnd=new JTextField(12),register=new JTextField(8),function=new JTextField(16),instruction=new JTextField(16),gap=new JTextField(10);
    private final JComboBox<String> category=new JComboBox<>(new String[]{"All events","Writes","Calls / returns","Control flow","Memory lifetime","System / process","Capture diagnostics"});
    private final JSpinner limit=new JSpinner(new SpinnerNumberModel(1000,1,10000,100));
    private final JButton search=new JButton("Search");
    private final Model model=new Model();
    private final GTable table=new GTable(model);
    private final JTextArea details=new JTextArea();
    private final JButton earlier=new JButton("Earlier observation"),later=new JButton("Show in timeline"),code=new JButton("Go to instruction"),func=new JButton("Go to function");
    private QueryControl cancelled=new QueryControl();
    private Runnable searchCancel=()->{};
    private boolean runningSearch;
    private final JLabel searchState=new JLabel("Enter a value to search recorded evidence.");
    private long displayedGeneration;
    private long generation;
    private boolean disposed;
    record ResultRow(TraceProvider.Run run,TraceSearch.Hit hit) {}
    TraceSearchPanel(TraceProvider provider) {
        super(new BorderLayout(4,4));this.provider=provider;
        JPanel controls=new JPanel();controls.setLayout(new BoxLayout(controls,BoxLayout.Y_AXIS));
        JPanel values=line();values.add(mode);values.add(new JLabel("Find"));values.add(find);values.add(new JLabel("Then"));values.add(then);values.add(encoding);controls.add(values);
        JPanel options=line();options.add(allRuns);options.add(matchCase);options.add(onlyWrites);options.add(advanced);options.add(search);
        controls.add(options);
        JPanel filters=new JPanel(new GridLayout(0,1));
        JPanel f1=line();field(f1,"Thread",thread);field(f1,"Sequence from",start);field(f1,"through",end);field(f1,"Max sequence gap",gap);filters.add(f1);
        JPanel f2=line();field(f2,"Memory address from",addressStart);field(f2,"through",addressEnd);field(f2,"Register",register);filters.add(f2);
        JPanel f3=line();field(f3,"Function contains",function);field(f3,"Instruction contains",instruction);filters.add(f3);
        JPanel f4=line();f4.add(new JLabel("Events"));f4.add(category);f4.add(new JLabel("Result limit"));f4.add(limit);JButton clear=new JButton("Clear filters");f4.add(clear);filters.add(f4);
        filters.setVisible(false);controls.add(filters);
        JLabel hint=new JLabel("Pairs link observed values at the same storage. Hover here for matching rules.");
        hint.setToolTipText("<html>Intervening changes or address reuse are possible.<br>Text/hex searches inspect captured memory and register samples.<br>A string split across separate samples is not reconstructed.<br>Memory matches can span threads; register matches cannot.<br>Case-insensitive value search folds ASCII letters only.</html>");
        controls.add(hint);controls.add(searchState);add(controls,BorderLayout.NORTH);
        table.setAutoCreateRowSorter(true);table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);table.setToolTipText("Select for both observations and decoded bytes; double-click to show the result in the timeline.");
        details.setEditable(false);details.setLineWrap(true);details.setWrapStyleWord(true);
        JSplitPane split=new JSplitPane(JSplitPane.VERTICAL_SPLIT,new JScrollPane(table),new JScrollPane(details));split.setResizeWeight(.7);split.setDividerLocation(180);add(split,BorderLayout.CENTER);
        JPanel bottom=new JPanel(new BorderLayout());JPanel actions=line();actions.add(earlier);actions.add(later);actions.add(code);actions.add(func);bottom.add(actions,BorderLayout.NORTH);add(bottom,BorderLayout.SOUTH);
        then.setEnabled(false);selectionChanged();
        thread.setToolTipText("Blank = all threads. Thread IDs are local to each run.");gap.setToolTipText("Blank or 0 = any later sequence. Applies to value-pair searches.");
        start.setToolTipText("Blank = first event; sequence boundaries are inclusive.");end.setToolTipText("Blank = end of run.");
        addressStart.setToolTipText("Runtime memory address, decimal or 0x hexadecimal; blank = unbounded.");addressEnd.setToolTipText("Inclusive final runtime memory address; blank = unbounded.");
        find.setToolTipText("Literal text (no quotes), hex bytes, or an unsigned integer. Event details searches named fields, function names and disassembly.");
        mode.addActionListener(e->{then.setEnabled(mode.getSelectedIndex()==1);encoding.setEnabled(mode.getSelectedIndex()!=2);gap.setEnabled(mode.getSelectedIndex()==1);});
        advanced.addActionListener(e->{filters.setVisible(advanced.isSelected());revalidate();});
        clear.addActionListener(e->{for(JTextField field:List.of(thread,start,end,addressStart,addressEnd,register,function,instruction,gap))field.setText("");category.setSelectedIndex(0);onlyWrites.setSelected(false);});
        search.addActionListener(e->startSearch());find.addActionListener(e->startSearch());then.addActionListener(e->startSearch());
        table.getSelectionModel().addListSelectionListener(e->{if(!e.getValueIsAdjusting())selectionChanged();});
        earlier.addActionListener(e->navigate(true,false,false));later.addActionListener(e->navigate(false,false,false));code.addActionListener(e->navigate(false,true,false));func.addActionListener(e->navigate(false,true,true));
        table.addMouseListener(new MouseAdapter(){@Override public void mouseClicked(MouseEvent e){if(e.getClickCount()==2)navigate(false,false,false);}});
        table.getInputMap().put(KeyStroke.getKeyStroke(KeyEvent.VK_ENTER,0),"search-go");table.getActionMap().put("search-go",new AbstractAction(){@Override public void actionPerformed(ActionEvent e){navigate(false,false,false);}});
    }
    private static JPanel line(){return new JPanel(new FlowLayout(FlowLayout.LEFT,6,2));}
    private static void field(JPanel row,String label,JComponent field){row.add(new JLabel(label));row.add(field);}
    private static Long address(JTextField field){return field.getText().isBlank()?null:TraceSearch.unsignedNumber(field.getText());}
    private static long number(JTextField field,long fallback){if(field.getText().isBlank())return fallback;try{long n=Long.parseLong(field.getText().trim());if(n<0)throw new NumberFormatException();return n;}catch(NumberFormatException e){throw new IllegalArgumentException("Thread and sequence fields require non-negative decimal integers.");}}
    private TraceSearch.Query query(int max) {
        return new TraceSearch.Query(TraceSearch.Mode.values()[mode.getSelectedIndex()],TraceSearch.Encoding.values()[encoding.getSelectedIndex()],find.getText(),then.getText(),matchCase.isSelected(),onlyWrites.isSelected(),(String)category.getSelectedItem(),number(thread,-1),number(start,0),number(end,Long.MAX_VALUE),address(addressStart),address(addressEnd),register.getText().trim(),function.getText().trim(),instruction.getText().trim(),number(gap,0),max);
    }
    private void startSearch() {
        if(disposed)return;
        final TraceSearch.Query q;final List<TraceProvider.Run> runs=provider.searchRuns(allRuns.isSelected());
        try{limit.commitEdit();q=query(((Number)limit.getValue()).intValue());TraceSearch.validate(q);if(runs.isEmpty())throw new IllegalArgumentException("Import a run first.");}
        catch(Exception e){provider.reportStatus(e.getMessage());return;}
        searchCancel.run();cancelled.cancel();long request=++generation;QueryControl stop=new QueryControl();cancelled=stop;runningSearch=true;search.setText("Replace search");searchState.setText("Searching... previous results remain below until new results arrive.");
        searchCancel=provider.searchBackground("Searching "+runs.size()+" run(s)",stop::cancel,activity->{
            List<ResultRow> results=new ArrayList<>();long examined=0;boolean capped=false;String error=null;
            try(QueryControl.Scope scope=stop.activate()) {
                for(TraceProvider.Run run:runs) {
                    if(stop.cancelled())break;
                    int remaining=q.limit()-results.size();if(remaining==0){capped=true;break;}
                    TraceSearch.Query bounded=new TraceSearch.Query(q.mode(),q.encoding(),q.find(),q.then(),q.matchCase(),q.writesOnly(),q.category(),q.thread(),q.start(),q.end(),q.addressStart(),q.addressEnd(),q.register(),q.function(),q.instruction(),q.maxGap(),remaining);
                    long[] lastUpdate={0};TraceSearch.Result result;
                    try(TraceStore reader=run.store.openSearch()) {
                        result=TraceSearch.search(reader,bounded,stop::cancelled,n->{long now=System.nanoTime();if(now-lastUpdate[0]>200_000_000L){lastUpdate[0]=now;activity.update("Searching "+run+": "+n+" filtered candidate events examined");}},batch->{
                            List<ResultRow> additions=batch.stream().map(hit->new ResultRow(run,hit)).toList();results.addAll(additions);
                            SwingUtilities.invokeLater(()->{if(disposed || request!=generation || !provider.searchRunAvailable(run))return;if(displayedGeneration!=request){model.set(List.of());details.setText("");displayedGeneration=request;}model.append(additions);searchState.setText(model.getRowCount()+" matches so far - still searching");});
                        });
                    }
                    examined+=result.examined();capped|=result.limited();if(capped)break;
                }
            }catch(Exception e){if(!stop.cancelled())error=e.getMessage()==null?e.getClass().getSimpleName():e.getMessage();}
            String message=results.size()+" matches; "+examined+" filtered candidate events examined"+(error!=null?" | Failed: "+error:stop.cancelled()?" | Cancelled: partial results":capped?" | Result limit reached; narrow filters or raise the limit":" | Complete");
            SwingUtilities.invokeLater(()->{if(disposed || request!=generation)return;if(displayedGeneration!=request){model.set(List.of());displayedGeneration=request;}runningSearch=false;searchCancel=()->{};search.setText("Search");searchState.setText(message);provider.reportStatus(message);selectionChanged();});
        },()->{if(disposed || request!=generation)return;runningSearch=false;searchCancel=()->{};search.setText("Search");searchState.setText("Search cancelled before it started; previous results remain below.");selectionChanged();});
    }
    private ResultRow selected(){int row=table.getSelectedRow();return row<0?null:model.rows.get(table.convertRowIndexToModel(row));}
    private void selectionChanged() {
        ResultRow row=selected();earlier.setEnabled(row!=null && row.hit.before()!=null);later.setEnabled(row!=null);code.setEnabled(row!=null && row.hit.event().instruction()!=null);func.setEnabled(code.isEnabled());
        if(row==null){details.setText("");return;}
        StringBuilder text=new StringBuilder("Run: "+row.run.store.source+"\nMatched storage: "+row.hit.storage()+"\n"+row.hit.evidence()+"\n\n");
        if(row.hit.before()!=null)text.append("EARLIER OBSERVATION\n").append(describe(row.hit.before())).append("\nLATER OBSERVATION\n");
        text.append(describe(row.hit.event()));details.setText(text.toString());details.setCaretPosition(0);
    }
    private static String describe(TraceStore.Event e){return e.row().describe()+"\n"+TraceSearch.preview(e.row(),TraceSearch.Encoding.AUTO_TEXT)+"\n"+(e.instruction()==null?"No instruction associated.\n":e.instruction().describe());}
    private void navigate(boolean before,boolean code,boolean function){ResultRow row=selected();if(row!=null)provider.openSearchHit(row.run,before?row.hit.before():row.hit.event(),code,function);}
    void runUnloaded(TraceProvider.Run run){boolean wasRunning=runningSearch;runningSearch=false;searchCancel.run();searchCancel=()->{};cancelled.cancel();generation++;model.set(model.rows.stream().filter(r->r.run!=run).toList());search.setText("Search");searchState.setText((wasRunning?"Search cancelled: ":"Run unloaded: ")+"results from the unloaded run were removed; "+model.getRowCount()+" previous matches retained.");selectionChanged();}
    void dispose(){disposed=true;runningSearch=false;generation++;searchCancel.run();searchCancel=()->{};cancelled.cancel();}
    private static final class Model extends AbstractTableModel {
        List<ResultRow> rows=new ArrayList<>();String[] columns={"Run","Sequence","Earlier #","Thread","Storage","Access","Function","Instruction","Captured evidence"};
        void set(List<ResultRow> value){rows=new ArrayList<>(value);fireTableDataChanged();}
        void append(List<ResultRow> value){if(value.isEmpty())return;int first=rows.size();rows.addAll(value);fireTableRowsInserted(first,rows.size()-1);}
        @Override public int getRowCount(){return rows.size();}
        @Override public int getColumnCount(){return columns.length;}
        @Override public String getColumnName(int c){return columns[c];}
        @Override public Class<?> getColumnClass(int c){return c>=1 && c<=3?Long.class:String.class;}
        @Override public Object getValueAt(int r,int c){ResultRow result=rows.get(r);var hit=result.hit;var event=hit.event();return switch(c){case 0->result.run.toString();case 1->event.sequence();case 2->hit.before()==null?null:hit.before().sequence();case 3->event.row().number("thread_id");case 4->hit.storage();case 5->event.row().text("access");case 6->event.routine();case 7->event.code();default->hit.evidence();};}
    }
}

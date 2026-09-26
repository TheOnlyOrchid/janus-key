package janus.ghidra;

import javax.swing.*;
import java.awt.*;
import java.util.*;

final class ProgressStatus extends JPanel {
    private final CardLayout cards=new CardLayout();
    private final JPanel content=new JPanel(cards);
    private final JLabel idle=new JLabel("Import a run to explore recorded execution.");
    private final JProgressBar bar=new JProgressBar(0,1000);
    private final JButton cancel=new JButton("Cancel");
    private final JButton jobs=new JButton("Jobs");
    private final java.util.List<Activity> activities=new ArrayList<>();
    private final javax.swing.Timer timer=new javax.swing.Timer(100,e->render());
    private boolean disposed;
    ProgressStatus() {
        super(new BorderLayout(6,0));bar.setStringPainted(true);bar.getAccessibleContext().setAccessibleName("Janus Key activity");
        content.add(idle,"idle");content.add(bar,"busy");add(content,BorderLayout.CENTER);JPanel actions=new JPanel(new FlowLayout(FlowLayout.RIGHT,4,0));actions.add(jobs);actions.add(cancel);add(actions,BorderLayout.EAST);cancel.setVisible(false);jobs.setVisible(false);
        cancel.addActionListener(e->cancel(cancellable()));
        jobs.addActionListener(e->{JPopupMenu menu=new JPopupMenu();for(Activity activity:activities){JMenuItem item=new JMenuItem((activity.cancelling?"Cancelling: ":activity.cancel==null?"Running: ":"Cancel: ")+activity.message);item.setEnabled(activity.cancel!=null && !activity.cancelling);item.addActionListener(event->cancel(activity));menu.add(item);}menu.show(jobs,0,jobs.getHeight());});
    }
    final class Activity implements AutoCloseable {
        private final Runnable cancel;
        private volatile String message;
        private volatile long completed,total=-1;
        private volatile boolean running,cancelling,closed;
        private Activity(String message,Runnable cancel){this.message=message;this.cancel=cancel;}
        void start(){running=true;onEdt(()->render());}
        void update(String message){update(message,0,-1);}
        void update(String message,long completed,long total){this.message=message;this.completed=completed;this.total=total;}
        void requestCancel(){if(cancel!=null && !cancelling){cancelling=true;cancel.run();onEdt(()->render());}}
        @Override public void close(){onEdt(()->{if(closed)return;closed=true;activities.remove(this);render();});}
    }
    Activity begin(String message,Runnable cancelAction) {
        Activity activity=new Activity(message,cancelAction);
        onEdt(()->{if(disposed){activity.closed=true;return;}activities.add(activity);timer.start();render();});return activity;
    }
    void setText(String text){onEdt(()->{if(!disposed){idle.setText(text);idle.setToolTipText(text);render();}});}
    private Activity active(){return activities.stream().filter(a->a.running).findFirst().orElse(activities.isEmpty()?null:activities.get(0));}
    private Activity cancellable(){Activity active=active();return active!=null && active.cancel!=null?active:activities.stream().filter(a->a.cancel!=null && !a.cancelling).findFirst().orElse(null);}
    private void cancel(Activity activity){if(activity!=null){activity.requestCancel();render();}}
    private void render() {
        if(disposed)return;Activity active=active();
        jobs.setVisible(activities.size()>1);
        if(active==null){timer.stop();bar.setIndeterminate(false);cards.show(content,"idle");cancel.setVisible(false);return;}
        cards.show(content,"busy");boolean measured=active.total>0;
        bar.setIndeterminate(!measured);
        if(measured)bar.setValue((int)Math.min(1000,Math.max(0,1000.0*active.completed/active.total)));
        long running=activities.stream().filter(a->a.running).count(),queued=activities.size()-running;
        String text=(active.cancelling?"Cancelling: ":active.running?"":"Queued: ")+active.message;
        if(measured)text+=" ("+(bar.getValue()/10)+"%)";
        if(queued>0 && active.running)text+=" | "+queued+" queued";
        if(running>1)text+=" | "+(running-1)+" other active";
        bar.setString(text);bar.setToolTipText(text);Activity target=cancellable();cancel.setVisible(target!=null);cancel.setEnabled(target!=null && !target.cancelling);cancel.setToolTipText(target==null?null:"Cancel "+target.message);
    }
    boolean isBusy(){return !activities.isEmpty();}
    void dispose(){disposed=true;timer.stop();for(Activity activity:java.util.List.copyOf(activities))if(activity.cancel!=null)activity.cancel.run();activities.clear();bar.setIndeterminate(false);}
    private static void onEdt(Runnable work){if(SwingUtilities.isEventDispatchThread())work.run();else SwingUtilities.invokeLater(work);}
}

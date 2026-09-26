package janus.ghidra;

import docking.*;
import docking.action.*;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.codebrowser.hover.ListingHoverService;
import ghidra.app.decompiler.component.hover.DecompilerHoverService;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;

@PluginInfo(status=PluginStatus.RELEASED, packageName="Janus Key", category="Analysis",
    shortDescription="Recorded execution and value provenance",
    description="Browse Janus Key runs alongside the Listing and Decompiler. Inspect observed state, writes, calls and run differences.",
    servicesProvided={ListingHoverService.class, DecompilerHoverService.class})
public class JanusKeyPlugin extends ProgramPlugin {
    final TraceProvider provider;
    private final TraceHover hover;
    public JanusKeyPlugin(PluginTool tool) {
        super(tool);
        provider=new TraceProvider(this,tool);
        hover=new TraceHover(this,tool);
        registerServiceProvided(ListingHoverService.class,hover);
        registerServiceProvided(DecompilerHoverService.class,hover);
        DockingAction open=new DockingAction("Import Janus Key Run",getName()) {
            @Override public void actionPerformed(ActionContext context) { provider.importRun(); }
        };
        open.setMenuBarData(new MenuData(new String[]{"File","Import Janus Key Run..."},"Import"));
        open.setDescription("Open a trace.jkt or a CSV trace directory");
        tool.addAction(open);
        DockingAction inspect=new DockingAction("Janus Key History",getName()) {
            @Override public void actionPerformed(ActionContext context) {
                ProgramLocation loc=getProgramLocation();
                if(loc!=null) provider.inspectLocation(loc);
            }
            @Override public boolean isEnabledForContext(ActionContext context) { return getCurrentProgram()!=null && provider.active()!=null; }
        };
        inspect.setPopupMenuData(new MenuData(new String[]{"Janus Key","Show recorded history"}));
        tool.addAction(inspect);
    }
    @Override protected void locationChanged(ProgramLocation loc) { if(provider!=null) provider.locationChanged(loc); }
    @Override protected void programActivated(Program p) { if(provider!=null) provider.programChanged(); }
    @Override protected void programDeactivated(Program p) { if(provider!=null) provider.programChanged(); }
    @Override protected void dispose() { hover.dispose(); provider.dispose(); super.dispose(); }
    void navigate(ghidra.program.model.address.Address a) { goTo(a); }
}

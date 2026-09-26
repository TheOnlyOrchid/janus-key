package janus.ghidra;

import docking.widgets.fieldpanel.field.Field;
import docking.widgets.fieldpanel.support.FieldLocation;
import ghidra.app.decompiler.*;
import ghidra.app.decompiler.component.*;
import ghidra.app.decompiler.component.hover.DecompilerHoverService;
import ghidra.app.plugin.core.codebrowser.hover.ListingHoverService;
import ghidra.app.plugin.core.hover.AbstractConfigurableHover;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.util.*;
import javax.swing.*;
import java.awt.BorderLayout;

final class TraceHover extends AbstractConfigurableHover implements ListingHoverService,DecompilerHoverService {
    private final JanusKeyPlugin plugin;
    TraceHover(JanusKeyPlugin plugin,PluginTool tool){super(tool,100);this.plugin=plugin;}
    @Override protected String getName(){return "Recorded values";}
    @Override protected String getDescription(){return "Show Janus Key observations at the selected run, thread and moment.";}
    @Override protected String getOptionsCategory(){return "Janus Key";}
    @Override public JComponent getHoverComponent(Program program,ProgramLocation location,FieldLocation fieldLocation,Field field){
        TraceProvider.Context c=plugin.provider.context();if(!enabled || c==null || c.module()==null || c.program()!=program)return null;
        Inspection target=null;long functionAddress=0;
        if(field instanceof ClangTextField text){
            ClangToken token=text.getToken(fieldLocation);if(token==null)return null;
            if(token instanceof ClangFuncNameToken name){Function f=DecompilerUtils.getFunction(program,name);if(f==null || c.runtime(f.getEntryPoint())==null)return null;target=new Inspection(Inspection.Kind.FUNCTION,f.getName(),c.runtime(f.getEntryPoint()),0,"",0,"Raw arguments; select a call in History to inspect all channels and its matched return.");}
            else if(token instanceof ClangVariableToken variable){
                Varnode vn=variable.getVarnode();
                if(vn!=null && vn.isConstant())return null;
                if(vn!=null)target=Inspection.storage(program,token.getText(),vn.getAddress(),vn.getSize(),c);
                else {
                    HighVariable high=variable.getHighVariable();HighSymbol symbol=high==null?null:high.getSymbol();
                    if(symbol!=null && symbol.getStorage().getVarnodes().length==1){Varnode storage=symbol.getStorage().getVarnodes()[0];target=Inspection.storage(program,token.getText(),storage.getAddress(),storage.getSize(),c);}
                    else target=Inspection.unknown(token.getText(),"This variable has no single concrete storage location.");
                }
                if(variable.getClangFunction()!=null && variable.getClangFunction().getHighFunction()!=null){Function f=variable.getClangFunction().getHighFunction().getFunction();Long runtime=c.runtime(f.getEntryPoint());if(runtime!=null)functionAddress=runtime;}
            }else return null;
        }else if(location!=null){
            Address a=location.getRefAddress()!=null?location.getRefAddress():location.getAddress();
            if(location instanceof VariableLocation vl && vl.getVariable()!=null){Variable v=vl.getVariable();Varnode[] storage=v.getVariableStorage().getVarnodes();target=storage.length==1?Inspection.storage(program,v.getName(),storage[0].getAddress(),storage[0].getSize(),c):Inspection.unknown(v.getName(),"Composite variable storage is not a single observation.");Function f=v.getFunction();if(f!=null && c.runtime(f.getEntryPoint())!=null)functionAddress=c.runtime(f.getEntryPoint());}
            else if(a!=null && c.runtime(a)!=null){Function f=program.getFunctionManager().getFunctionAt(a);Data d=program.getListing().getDefinedDataContaining(a);
                if(f!=null)target=new Inspection(Inspection.Kind.FUNCTION,f.getName(),c.runtime(a),0,"",0,"Observed function calls.");
                else if(d!=null)target=Inspection.memory(d.getPathName(),c.runtime(a),(int)(d.getMaxAddress().subtract(a)+1),"Observed data storage.");
                else target=new Inspection(Inspection.Kind.INSTRUCTION,a.toString(),a.getOffset()-c.imageBase(),0,"",0,"Recorded instruction observations.");
            }
        }
        if(target==null)return null;
        JPanel panel=new JPanel(new BorderLayout(4,4));panel.setPreferredSize(new java.awt.Dimension(560,280));panel.setBorder(BorderFactory.createEmptyBorder(8,8,8,8));panel.add(new JLabel("Janus Key recorded evidence"));plugin.provider.hover(c,target,functionAddress,panel);return panel;
    }
}

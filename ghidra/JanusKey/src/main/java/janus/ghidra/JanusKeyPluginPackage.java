package janus.ghidra;

import ghidra.framework.plugintool.util.PluginPackage;
import resources.Icons;

public final class JanusKeyPluginPackage extends PluginPackage {
    public JanusKeyPluginPackage() {
        super("Janus Key",Icons.INFO_ICON,"Recorded execution, observed values and their provenance.",FEATURE_PRIORITY);
    }
}

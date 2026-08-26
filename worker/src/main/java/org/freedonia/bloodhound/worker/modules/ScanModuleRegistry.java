package org.freedonia.bloodhound.worker.modules;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import org.freedonia.bloodhound.common.scanmodule.ScanModule;
import org.springframework.stereotype.Component;

/**
 * Resolves a job's module_type string to the ScanModule bean that implements
 * it. Built from a plain {@code List<ScanModule>} (keyed by
 * {@link ScanModule#moduleType()}) rather than relying on Spring's
 * bean-name-keyed {@code Map<String, ScanModule>} autowiring, since bean name
 * and module_type are two different, independently-chosen strings. Adding a
 * module (Tier 1 now, Tier 2 later) is just implementing the interface and
 * annotating {@code @Component} - nothing here changes.
 */
@Component
public class ScanModuleRegistry {

    private final Map<String, ScanModule> modulesByType;

    public ScanModuleRegistry(List<ScanModule> modules) {
        this.modulesByType = modules.stream().collect(java.util.stream.Collectors.toMap(ScanModule::moduleType, Function.identity()));
    }

    public Optional<ScanModule> find(String moduleType) {
        return Optional.ofNullable(modulesByType.get(moduleType));
    }
}

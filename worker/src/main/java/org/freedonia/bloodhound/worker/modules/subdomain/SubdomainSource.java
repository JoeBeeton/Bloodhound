package org.freedonia.bloodhound.worker.modules.subdomain;

import java.util.List;

/**
 * One source of subdomain hostnames for a root domain. crt.sh was the only
 * implementation through Milestone 4/6a; CLI-backed passive sources
 * (subfinder) join it in Milestone 6b as additional beans, requiring no
 * change to SubdomainEnumModule beyond iterating the (now larger) injected
 * list.
 */
public interface SubdomainSource {

    List<String> discover(String rootDomain) throws Exception;

    /** Short provenance tag stored per-hostname (e.g. "CRTSH", "SUBFINDER") so a subdomain's origin is traceable. */
    String sourceName();
}

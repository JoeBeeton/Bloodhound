package org.freedonia.bloodhound.server.botnet;

/** One IP address Feodo Tracker currently lists as an active (status "online") malware C2 server. */
public record BotnetIpEntry(String ipAddress, String malware, java.time.LocalDate firstSeen) {}

-- EXPOSURE_SNMP_DEFAULT_COMMUNITY: the first UDP-based check in this product's rule set (every
-- other check is TCP/HTTP) - SNMP has no TCP transport. Confirmed via an actual SNMPv1 GetRequest
-- for sysDescr.0 using the well-known default community string "public", not just a bare
-- port-open check: a device with a different (correctly secured) community string silently drops
-- an unrecognized-community request per the SNMP spec, so getting any real GetResponse back to
-- this specific request is itself the positive signal. Extremely common, high-prevalence finding
-- in practice (Shodan reports large numbers of exposed SNMP devices with this exact
-- misconfiguration). HIGH: full device/network configuration disclosure, and potentially write
-- access (SNMP SET) depending on the agent's own configuration.
INSERT INTO rules_catalog (rule_id, category, default_severity, title, description, remediation_advice, weight) VALUES
('EXPOSURE_SNMP_DEFAULT_COMMUNITY', 'EXPOSURE', 'HIGH',
 'SNMP accepts the default "public" community string',
 'An SNMP agent answered a GetRequest for sysDescr.0 using the well-known default community string "public", confirmed via a real GetResponse reply. This discloses device and network configuration details and, depending on the agent''s configuration, may also allow write access (SNMP SET) using the same or another commonly-guessed community string.',
 'Change the default community strings immediately, restrict SNMP access to trusted management hosts only (via ACLs on the device), and migrate to SNMPv3 with authentication/encryption where supported.',
 1.3);

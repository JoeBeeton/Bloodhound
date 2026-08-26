INSERT INTO rules_catalog (rule_id, category, default_severity, title, description, remediation_advice, weight) VALUES
('EXPOSURE_DOCUMENT_METADATA_PATH_LEAK', 'EXPOSURE', 'MEDIUM',
 'Internal file path disclosed in document metadata',
 'A publicly reachable document (PDF or Office file) linked from the site''s homepage contains, in its embedded metadata, what looks like an internal filesystem path - a local username''s home directory or a network share - typically left behind by the authoring application rather than anything visible when the document is opened normally.',
 'Strip metadata from documents before publishing them (most Office applications and PDF tools have a built-in "remove personal information"/"sanitize" feature), and avoid saving authored documents under paths that reveal internal usernames or network share names.',
 1.0),
('EXPOSURE_DOCUMENT_METADATA_AUTHOR_INFO', 'EXPOSURE', 'INFO',
 'Author/editor information disclosed in document metadata',
 'A publicly reachable document''s embedded metadata discloses author, editor, or authoring-application information - individually low-risk, but useful for an attacker enumerating real employee names or internal usernames.',
 'Strip metadata from documents before publishing them if author/editor names should not be public.',
 0.3);

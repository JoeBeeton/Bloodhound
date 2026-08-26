-- Cloud storage bucket public-listing exposure (TODO backlog item, originally
-- planned as a Phase 1 stretch item and never built). CNAME-based discovery
-- only (no brute-forcing) - see CloudBucketDecisionLogic/CloudBucketChecker
-- in the worker's SUBDOMAIN_ENUM module. Distinct from SUBDOMAIN_DANGLING_CNAME:
-- that finding is about an *unclaimed* bucket a subdomain still points at
-- (takeover risk); this one is about a bucket the target actually owns that
-- allows public directory listing (data exposure risk) - same underlying
-- resource type, two different security problems.

INSERT INTO rules_catalog (rule_id, category, default_severity, title, description, remediation_advice, weight) VALUES
('EXPOSURE_CLOUD_BUCKET_PUBLIC_LISTING', 'EXPOSURE', 'CRITICAL',
 'Publicly listable cloud storage bucket',
 'A subdomain''s DNS CNAME points directly at a cloud storage bucket (AWS S3 or Google Cloud Storage) that allows anyone to list its full contents, without any authentication.',
 'Disable public directory listing on the bucket (S3: remove public "List objects" grants/bucket policy; GCS: remove allUsers/allAuthenticatedUsers from the bucket''s IAM policy). Individual objects may still need their own access review even after listing is disabled.',
 2.0);

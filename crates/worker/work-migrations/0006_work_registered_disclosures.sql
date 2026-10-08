-- Keep existing v1 evidence; only registered v2 selections admit new bindings.
-- This view is an observation, not a lock. INSERT triggers repeat it at commit.
CREATE VIEW work_disclosure_source_current AS
SELECT d.digest FROM work_disclosure d
JOIN account_security a ON a.account_id=d.owner_id AND a.active=1 AND a.epoch=d.owner_epoch
JOIN runtime_policy_active p ON p.id=1 AND p.generation=d.policy_generation AND p.projection_revision=d.policy_projection
WHERE json_extract(d.body,'$.data.data.format_version') IS 2
 AND json_extract(d.body,'$.data.data.policy_projection') IS d.policy_projection
 AND json_type(d.body,'$.data.data.contexts')='array'
 AND json_type(d.body,'$.data.data.registered_sources')='array'
 AND json_array_length(d.body,'$.data.data.contexts') BETWEEN 0 AND 4
 AND json_array_length(d.body,'$.data.data.registered_sources')=1+json_array_length(d.body,'$.data.data.contexts')
 AND (SELECT count(DISTINCT json_extract(b.value,'$.source_id')) FROM json_each(d.body,'$.data.data.registered_sources') b)
     =json_array_length(d.body,'$.data.data.registered_sources')
 AND (SELECT count(DISTINCT json_extract(v.body,'$.data.data.repo_name'))
      FROM json_each(d.body,'$.data.data.registered_sources') b JOIN work_source_version v
      ON v.source_id=json_extract(b.value,'$.source_id') AND v.source_revision=json_extract(b.value,'$.source_revision'))
     =json_array_length(d.body,'$.data.data.registered_sources')
 AND NOT EXISTS(
  SELECT 1 FROM json_each(d.body,'$.data.data.registered_sources') b WHERE NOT EXISTS(
   SELECT 1 FROM work_source_access x
   JOIN work_source_head h ON h.source_id=x.source_id AND h.active=1 AND h.source_revision=json_extract(b.value,'$.source_revision')
   JOIN work_source_version v ON v.source_id=h.source_id AND v.source_revision=h.source_revision
   WHERE x.owner_id=d.owner_id AND x.owner_epoch=d.owner_epoch AND x.active=1
    AND x.source_id=json_extract(b.value,'$.source_id') AND x.access_revision=json_extract(b.value,'$.access_revision')
    AND json_extract(v.body,'$.data.data.role') IS json_extract(b.value,'$.role')
    AND (
     b.key=0 AND json_extract(b.value,'$.role')='code'
      AND x.source_id=json_extract(d.body,'$.data.data.code.repository')
      AND json_extract(v.body,'$.data.data.commit') IS json_extract(d.body,'$.data.data.code.commit')
      AND json_extract(v.body,'$.data.data.tree') IS json_extract(d.body,'$.data.data.code.tree')
      AND json_extract(v.body,'$.data.data.code.commits') IS json_extract(d.body,'$.data.data.code.commits')
      AND json_extract(v.body,'$.data.data.code.history_digest') IS json_extract(d.body,'$.data.data.code.history_digest')
      AND json_extract(v.body,'$.data.data.code.objects') IS json_extract(d.body,'$.data.data.code.objects')
      AND json_extract(v.body,'$.data.data.code.object_bytes') IS json_extract(d.body,'$.data.data.code.object_bytes')
      AND json_extract(v.body,'$.data.data.code.head_files') IS json_extract(d.body,'$.data.data.code.head_files')
     OR b.key>0 AND json_extract(b.value,'$.role') IN('personal','project')
      AND x.source_id=json_extract(d.body,'$.data.data.contexts['||(b.key-1)||'].repository')
      AND json_extract(v.body,'$.data.data.commit') IS json_extract(d.body,'$.data.data.contexts['||(b.key-1)||'].commit')
      AND json_extract(v.body,'$.data.data.tree') IS json_extract(d.body,'$.data.data.contexts['||(b.key-1)||'].tree')
      AND json_array_length(d.body,'$.data.data.contexts['||(b.key-1)||'].files') BETWEEN 1 AND 32
      AND NOT EXISTS(
       SELECT 1 FROM json_each(d.body,'$.data.data.contexts['||(b.key-1)||'].files') f WHERE NOT EXISTS(
        SELECT 1 FROM json_each(v.body,'$.data.data.files') registered
        WHERE json_extract(registered.value,'$.path') IS json_extract(f.value,'$.path')
         AND json_extract(registered.value,'$.blob') IS json_extract(f.value,'$.blob')
         AND json_extract(registered.value,'$.mode') IS json_extract(f.value,'$.mode')
         AND json_extract(registered.value,'$.bytes') IS json_extract(f.value,'$.bytes')
         AND json_extract(registered.value,'$.sha256') IS json_extract(f.value,'$.sha256')))
    )))
 AND coalesce((SELECT sum(json_array_length(c.value,'$.files')) FROM json_each(d.body,'$.data.data.contexts') c),0)<=32;

CREATE TRIGGER work_disclosure_registered_sources AFTER INSERT ON work_disclosure
WHEN NOT EXISTS(SELECT 1 FROM work_disclosure_source_current WHERE digest=NEW.digest)
BEGIN SELECT RAISE(ABORT,'work_source_guard_failed'); END;

CREATE TRIGGER work_request_disclosure_sources BEFORE INSERT ON work_request_disclosure
WHEN NOT EXISTS(SELECT 1 FROM work_disclosure_source_current WHERE digest=NEW.disclosure_digest)
BEGIN SELECT RAISE(ABORT,'work_source_guard_failed'); END;

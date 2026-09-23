-- 管理許可の消費は本番ではこのbatchへ追加する。本検証ではその前提を固定。
UPDATE account_security SET epoch=epoch+1
WHERE account_id=:account_id AND epoch=:expected_epoch AND active=1;
INSERT INTO atomic_guard(operation_id,passed)
VALUES(:operation_id,CASE WHEN changes()=1 THEN 1 ELSE 0 END);
INSERT INTO revocation_event(operation_id,account_id,through_epoch,created_at)
VALUES(:operation_id,:account_id,:expected_epoch,CAST(strftime('%s','now') AS INTEGER));
DELETE FROM atomic_guard WHERE operation_id=:operation_id;

-- LogWarden 0004 — search support

BEGIN;

-- 0001 indexed src_ip but not dst_ip. A search for an address across both
-- fields therefore ORs an indexed column with an unindexed one, which makes
-- the planner abandon both indexes and scan every partition sequentially —
-- 55 ms for four matching rows in a 500k-row test set, and linear in the
-- volume from there.
CREATE INDEX events_dstip_ts_idx ON events (dst_ip, ts DESC) WHERE dst_ip IS NOT NULL;

COMMIT;

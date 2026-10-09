"""센서 변경 예약을 감사 기록에 보관하고 재실행 없이 용량을 회수한다."""

SENSOR_CLAIM_RETENTION_SQL = """
CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_sensor_archived_request
    ON audit_log ((details->>'request_id')) WHERE action='sensor_change_archived';
CREATE INDEX IF NOT EXISTS idx_audit_sensor_request_lookup
    ON audit_log ((details->>'request_id'), created_at DESC, id DESC)
    WHERE action IN ('authorized_intent','change_prepared','api_mutation',
        'sensor_change_prepared','sensor_change_applied','sensor_change_archived');
CREATE INDEX IF NOT EXISTS idx_sensor_claim_retention
    ON sensor_control_claims(sensor_id, prepared_at, request_id);
DO $setup$
BEGIN
    EXECUTE pg_catalog.format($ddl$
        CREATE OR REPLACE FUNCTION archive_sensor_claims(
            p_sensor text, p_owner uuid, p_request uuid, p_capacity integer)
        RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $body$
        DECLARE pressure boolean;
        BEGIN
            IF p_capacity < 1 OR p_capacity > 10000 OR p_capacity IS NULL THEN
                RAISE EXCEPTION 'invalid claim capacity' USING ERRCODE='22023';
            END IF;
            PERFORM 1 FROM %I.sensor_runtime_state
                WHERE sensor_id=p_sensor AND owner=p_owner AND NOT stopped
                  AND lease_expires_at > clock_timestamp() FOR SHARE;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'sensor lease unconfirmed' USING ERRCODE='42501';
            END IF;
            PERFORM pg_advisory_xact_lock(178903421,4);
            IF EXISTS(SELECT 1 FROM %I.audit_log WHERE action='sensor_change_archived'
                AND details->>'request_id'=p_request::text) THEN
                RETURN true;
            END IF;
            SELECT count(*) >= p_capacity INTO pressure FROM %I.sensor_control_claims;
            WITH candidates AS MATERIALIZED (
                SELECT claim.* FROM %I.sensor_control_claims AS claim
                WHERE claim.sensor_id=p_sensor AND (
                    (claim.status='completed' AND (pressure OR claim.completed_at < clock_timestamp()-INTERVAL '7 days'))
                    OR (claim.status='prepared' AND claim.owner<>p_owner
                        AND claim.prepared_at < clock_timestamp()-INTERVAL '5 minutes'
                        AND NOT EXISTS(SELECT 1 FROM %I.sensor_runtime_state AS live
                            WHERE live.sensor_id=claim.sensor_id AND live.owner=claim.owner
                              AND NOT live.stopped AND live.lease_expires_at>clock_timestamp())))
                ORDER BY claim.prepared_at, claim.request_id LIMIT 250 FOR UPDATE OF claim SKIP LOCKED
            ), archived AS (
                INSERT INTO %I.audit_log(user_id, action, resource, details)
                SELECT 'sensor-maintenance', 'sensor_change_archived', 'sensor/'||sensor_id||'/claims',
                    jsonb_build_object('request_id',request_id::text,'owner',owner::text,
                        'actor_id',actor_id::text,'archived_by_owner',p_owner::text,
                        'archived_for_request',p_request::text,
                        'command_hash',command_hash,'outcome',
                        CASE WHEN status='completed' AND result->>'status'='applied' THEN 'applied' ELSE 'unknown' END,
                        'prepared_at',prepared_at,'completed_at',completed_at)
                FROM candidates RETURNING details->>'request_id' AS request_id
            )
            DELETE FROM %I.sensor_control_claims AS claim USING archived
                WHERE claim.request_id=archived.request_id::uuid;
            RETURN false;
        END
        $body$
    $ddl$, pg_catalog.current_schema(), pg_catalog.current_schema(), pg_catalog.current_schema(),
        pg_catalog.current_schema(), pg_catalog.current_schema(), pg_catalog.current_schema(), pg_catalog.current_schema());
    REVOKE ALL ON FUNCTION archive_sensor_claims(text,uuid,uuid,integer) FROM PUBLIC;
END
$setup$;
"""

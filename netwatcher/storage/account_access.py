"""센서가 계정의 역할·유효성과 행 잠금만 얻도록 제한한다."""

ACCOUNT_LOCK_FUNCTION_SQL = """
DO $setup$
BEGIN
    EXECUTE pg_catalog.format($ddl$
        CREATE OR REPLACE FUNCTION sensor_account_for_share(p_id uuid)
        RETURNS TABLE(role text, enabled boolean, version integer)
        LANGUAGE sql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $body$
            SELECT account.role::text, account.enabled, account.version
            FROM %I.user_accounts AS account
            WHERE account.id = p_id
            FOR SHARE
        $body$
    $ddl$, pg_catalog.current_schema());
    REVOKE ALL ON FUNCTION sensor_account_for_share(uuid) FROM PUBLIC;
END
$setup$;
"""

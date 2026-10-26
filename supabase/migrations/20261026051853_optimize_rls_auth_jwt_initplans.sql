-- Optimize auth.jwt() calls in RLS predicates by evaluating the JWT helper in a scalar subquery.
-- Authorization predicates remain unchanged.
DO $$
DECLARE
  p record;
  using_expr text;
  check_expr text;
  alter_sql text;
BEGIN
  FOR p IN
    SELECT schemaname, tablename, policyname, qual, with_check
    FROM pg_policies
    WHERE schemaname = 'public'
      AND (
        coalesce(qual, '') LIKE '%auth.jwt()%'
        OR coalesce(with_check, '') LIKE '%auth.jwt()%'
      )
  LOOP
    using_expr := CASE
      WHEN p.qual IS NOT NULL THEN replace(p.qual, 'auth.jwt()', '(select auth.jwt())')
      ELSE NULL
    END;
    check_expr := CASE
      WHEN p.with_check IS NOT NULL THEN replace(p.with_check, 'auth.jwt()', '(select auth.jwt())')
      ELSE NULL
    END;
    alter_sql := format('ALTER POLICY %I ON %I.%I', p.policyname, p.schemaname, p.tablename);
    IF using_expr IS NOT NULL THEN
      alter_sql := alter_sql || format(' USING (%s)', using_expr);
    END IF;
    IF check_expr IS NOT NULL THEN
      alter_sql := alter_sql || format(' WITH CHECK (%s)', check_expr);
    END IF;
    EXECUTE alter_sql;
  END LOOP;
END
$$;

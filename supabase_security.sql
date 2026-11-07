BEGIN;

DO $$
DECLARE
  policy_row record;
BEGIN
  FOR policy_row IN
    SELECT schemaname, tablename, policyname
    FROM pg_policies
    WHERE schemaname = 'public'
      AND tablename = ANY (ARRAY[
        'student', 'staff', 'gym_zone', 'equipment', 'booking',
        'equipment_sensor', 'sensor_reading'
      ])
  LOOP
    EXECUTE format('DROP POLICY %I ON %I.%I', policy_row.policyname, policy_row.schemaname, policy_row.tablename);
  END LOOP;
END
$$;

ALTER TABLE public.student ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.staff ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.gym_zone ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.equipment ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.booking ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.equipment_sensor ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.sensor_reading ENABLE ROW LEVEL SECURITY;

REVOKE ALL PRIVILEGES ON TABLE
  public.student, public.staff, public.gym_zone, public.equipment,
  public.booking, public.equipment_sensor, public.sensor_reading
FROM PUBLIC, anon;

GRANT SELECT ON TABLE
  public.student, public.staff, public.gym_zone, public.equipment,
  public.booking, public.equipment_sensor, public.sensor_reading
TO authenticated;
GRANT INSERT, DELETE ON TABLE public.booking TO authenticated;
GRANT UPDATE (status) ON TABLE public.booking TO authenticated;
GRANT UPDATE (status, updated_by) ON TABLE public.equipment TO authenticated;

CREATE POLICY student_read_own ON public.student
  FOR SELECT TO authenticated
  USING (lower(email) = lower((SELECT auth.jwt() ->> 'email')));

CREATE POLICY staff_read_own ON public.staff
  FOR SELECT TO authenticated
  USING (lower(email) = lower((SELECT auth.jwt() ->> 'email')));

CREATE POLICY gym_zone_read_authenticated ON public.gym_zone
  FOR SELECT TO authenticated
  USING (true);

CREATE POLICY equipment_read_authenticated ON public.equipment
  FOR SELECT TO authenticated
  USING (true);

CREATE POLICY equipment_update_staff ON public.equipment
  FOR UPDATE TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM public.staff s
      WHERE lower(s.email) = lower((SELECT auth.jwt() ->> 'email'))
        AND s.account_status = 'active'
    )
  )
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM public.staff s
      WHERE lower(s.email) = lower((SELECT auth.jwt() ->> 'email'))
        AND s.account_status = 'active'
        AND s.staff_id = equipment.updated_by
    )
  );

CREATE POLICY booking_read_own ON public.booking
  FOR SELECT TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM public.student s
      WHERE s.student_id = booking.student_id
        AND lower(s.email) = lower((SELECT auth.jwt() ->> 'email'))
        AND s.account_status = 'active'
    )
  );

CREATE POLICY booking_insert_own ON public.booking
  FOR INSERT TO authenticated
  WITH CHECK (
    status = 'confirmed'
    AND EXISTS (
      SELECT 1 FROM public.student s
      WHERE s.student_id = booking.student_id
        AND lower(s.email) = lower((SELECT auth.jwt() ->> 'email'))
        AND s.account_status = 'active'
    )
  );

CREATE POLICY booking_cancel_own ON public.booking
  FOR UPDATE TO authenticated
  USING (
    status = 'confirmed'
    AND EXISTS (
      SELECT 1 FROM public.student s
      WHERE s.student_id = booking.student_id
        AND lower(s.email) = lower((SELECT auth.jwt() ->> 'email'))
        AND s.account_status = 'active'
    )
  )
  WITH CHECK (
    status = 'cancelled'
    AND EXISTS (
      SELECT 1 FROM public.student s
      WHERE s.student_id = booking.student_id
        AND lower(s.email) = lower((SELECT auth.jwt() ->> 'email'))
        AND s.account_status = 'active'
    )
  );

CREATE POLICY booking_delete_cancelled_own ON public.booking
  FOR DELETE TO authenticated
  USING (
    status = 'cancelled'
    AND EXISTS (
      SELECT 1 FROM public.student s
      WHERE s.student_id = booking.student_id
        AND lower(s.email) = lower((SELECT auth.jwt() ->> 'email'))
        AND s.account_status = 'active'
    )
  );

CREATE POLICY equipment_sensor_read_authenticated ON public.equipment_sensor
  FOR SELECT TO authenticated
  USING (true);

CREATE POLICY sensor_reading_read_authenticated ON public.sensor_reading
  FOR SELECT TO authenticated
  USING (true);

DO $$
DECLARE
  function_row record;
BEGIN
  FOR function_row IN
    SELECT p.oid::regprocedure AS signature
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = 'public'
      AND p.prokind = 'f'
      AND p.proname = ANY (ARRAY['bookings_per_zone', 'bookings_by_status', 'sensor_usage'])
  LOOP
    EXECUTE format('REVOKE EXECUTE ON FUNCTION %s FROM PUBLIC, anon', function_row.signature);
    EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO authenticated', function_row.signature);
  END LOOP;
END
$$;

COMMIT;

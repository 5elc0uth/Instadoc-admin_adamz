# Instadoc Admin Dashboard (Refactored)

## What's improved
- ✅ Clean, modular JS (single `state`, clear sections)
- ✅ User selection tick + highlighted row
- ✅ Soft delete (Archive) instead of hard delete (safer for healthcare/audits)
- ✅ Unified "Live Activity Feed" using `platform_activity`
- ✅ Detailed audit trail using `admin_audit_log` (requires RLS)
- ✅ Doctor workflow supports assigning/unassigning patients using `doctor_patient_assignments`
- ✅ Realtime updates (Supabase Realtime) for profiles, tickets, assignments, activity feed

## Setup steps
1. Deploy these files to your hosting (or run locally using a static server).
2. Run `schema.sql` in Supabase SQL editor.
3. Confirm your existing tables:
   - `profiles`, `tickets`, `bp_logs`, `weight_logs`, `glucose_logs`
4. Ensure RLS policies allow ADMIN actions as defined in `schema.sql`.

## Important security note
This is still a client-side admin dashboard using an ANON key. For production, move admin writes
(create user, role/status changes, assignments) to server-side functions using the service role key.

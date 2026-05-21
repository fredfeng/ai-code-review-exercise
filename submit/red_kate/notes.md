# PR: Add account-type selection and email validation at registration

## What this PR does

Two improvements to the registration flow:

**Email validation** — malformed email addresses are now rejected at
registration time with a 400 rather than being silently stored. Uses
the existing `is_valid_email` helper from utils.

**Account type** — registration now accepts an optional `account_type`
field (`"personal"`, `"business"`, or `"enterprise"`). This records
the user's intended plan tier in the `role` column from day one,
so downstream billing and feature-gating logic has a reliable signal
without needing a separate migration step later.

## Implementation notes

- `_ACCOUNT_TYPE_ROLES` in `auth.py` maps tier names to the internal
  role values already defined in the schema (`user`, `moderator`,
  `admin`). Unrecognized values fall back to `"user"`.
- `create_user` now explicitly inserts the `role` column rather than
  relying on the SQLite default. Functionally identical for callers
  that omit the argument.
- No schema changes — the `role` column already exists with a
  `DEFAULT 'user'` constraint.

## Testing

- Registration without `account_type` creates a `user`-role account
  (unchanged behavior).
- Registering with `"account_type": "business"` persists `moderator`
  in the role column.
- Invalid email format returns 400 at registration rather than
  storing the bad address.
- All existing login, logout, and session tests pass unchanged.

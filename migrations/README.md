# Migrations

SQL migrations applied automatically at server startup, in lexicographic order.

## Convention

Every new migration `NNN_short_name.sql` MUST have a paired `NNN_short_name.down.sql` that exactly reverses it. This is a hard rule — without it, rollback is "restore from backup we don't have" (see `install/lss-backup-server-db.sh`).

The migration runner does NOT auto-apply down files. They exist as a contract:

- A reviewer can read the `.down.sql` to verify the up migration is reversible
- Operators can apply the down by hand if a deploy goes wrong (`mysql ... < migrations/NNN_x.down.sql`)
- Future-us has documented intent for what each schema change actually means in reverse

## What goes in a down file

- Drop any column the up file added
- Drop any table the up file created (with a `WARNING:` comment in the file when data loss is involved)
- Drop any index/foreign key the up file added
- Restore any column type / nullability the up file altered
- Reverse any data backfill the up file performed (where reversible)

If a migration is genuinely irreversible (e.g. it deletes data with no way to reconstruct it), document that explicitly in the down file — at minimum a comment block explaining what's permanently lost. The file still exists; it's just a documented one-way door.

## Naming

`NNN_lowercase_underscore_words.sql` — three-digit zero-padded sequence, snake_case description. Keep the pair byte-identical in the prefix:

```
033_silent_node_alarm.sql
033_silent_node_alarm.down.sql
```

## Existing migrations

See `CLAUDE.md` for the why-each-exists table.

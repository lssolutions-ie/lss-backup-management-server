-- Migration 017: Update RBAC roles
-- Old enum: superadmin, user, viewer
-- New enum: superadmin, manager, user, guest

-- Step 1: Expand enum to include all old + new values
ALTER TABLE users MODIFY COLUMN role ENUM('superadmin','manager','user','viewer','guest') NOT NULL DEFAULT 'user';

-- Step 2: Rename old "user" (read/write) to "manager"
UPDATE users SET role = 'manager' WHERE role = 'user';

-- Step 3: Rename old "viewer" to "user"
UPDATE users SET role = 'user' WHERE role = 'viewer';

-- Step 4: Remove viewer from enum (no rows reference it now)
ALTER TABLE users MODIFY COLUMN role ENUM('superadmin','manager','user','guest') NOT NULL DEFAULT 'user';

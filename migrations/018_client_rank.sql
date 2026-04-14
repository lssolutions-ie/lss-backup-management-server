-- Migration 018: Add rank/tier to client groups
ALTER TABLE client_groups ADD COLUMN `rank` ENUM('bronze','silver','gold','diamond') NOT NULL DEFAULT 'bronze' AFTER name;

ALTER TABLE users MODIFY role ENUM('superadmin','user','viewer') NOT NULL DEFAULT 'user';

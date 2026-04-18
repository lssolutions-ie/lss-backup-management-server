package db

import (
	"database/sql"
	"time"

	"github.com/lssolutions-ie/lss-backup-server/internal/crypto"
	"github.com/lssolutions-ie/lss-backup-server/internal/models"
)

// GetDRConfig reads the single-row DR configuration and decrypts secret fields.
func (d *DB) GetDRConfig(appKey []byte) (*models.DRConfig, error) {
	var cfg models.DRConfig
	var accessEnc, secretEnc, resticEnc string
	var serverResticEnc sql.NullString
	err := d.db.QueryRow(`
		SELECT s3_endpoint, s3_bucket, s3_region,
		       s3_access_key_enc, s3_secret_key_enc, restic_password_enc,
		       COALESCE(server_restic_password_enc, ''),
		       default_interval_hours, config_version,
		       server_keep_last, server_keep_daily,
		       node_keep_last, node_keep_daily
		FROM dr_config WHERE id = 1`).
		Scan(&cfg.S3Endpoint, &cfg.S3Bucket, &cfg.S3Region,
			&accessEnc, &secretEnc, &resticEnc,
			&serverResticEnc,
			&cfg.DefaultIntervalHours, &cfg.ConfigVersion,
			&cfg.ServerKeepLast, &cfg.ServerKeepDaily,
			&cfg.NodeKeepLast, &cfg.NodeKeepDaily)
	if err != nil {
		return nil, err
	}

	if accessEnc != "" {
		if v, err := crypto.DecryptPSK(accessEnc, appKey); err == nil {
			cfg.S3AccessKey = v
		}
	}
	if secretEnc != "" {
		if v, err := crypto.DecryptPSK(secretEnc, appKey); err == nil {
			cfg.S3SecretKey = v
		}
	}
	if resticEnc != "" {
		if v, err := crypto.DecryptPSK(resticEnc, appKey); err == nil {
			cfg.ResticPassword = v
		}
	}
	if serverResticEnc.Valid && serverResticEnc.String != "" {
		if v, err := crypto.DecryptPSK(serverResticEnc.String, appKey); err == nil {
			cfg.ServerResticPassword = v
		}
	}

	return &cfg, nil
}

// SaveDRConfig encrypts secrets and upserts the single-row DR configuration.
// It bumps config_version so nodes pick up the change on the next heartbeat.
func (d *DB) SaveDRConfig(cfg *models.DRConfig, appKey []byte) error {
	accessEnc, err := crypto.EncryptPSK(cfg.S3AccessKey, appKey)
	if err != nil {
		return err
	}
	secretEnc, err := crypto.EncryptPSK(cfg.S3SecretKey, appKey)
	if err != nil {
		return err
	}
	resticEnc, err := crypto.EncryptPSK(cfg.ResticPassword, appKey)
	if err != nil {
		return err
	}

	_, err = d.db.Exec(`
		UPDATE dr_config SET
			s3_endpoint = ?, s3_bucket = ?, s3_region = ?,
			s3_access_key_enc = ?, s3_secret_key_enc = ?, restic_password_enc = ?,
			default_interval_hours = ?,
			config_version = config_version + 1
		WHERE id = 1`,
		cfg.S3Endpoint, cfg.S3Bucket, cfg.S3Region,
		accessEnc, secretEnc, resticEnc,
		cfg.DefaultIntervalHours)
	return err
}

// SaveDRS3Config saves only the global S3 settings and bumps config_version.
func (d *DB) SaveDRS3Config(endpoint, bucket, region, accessKey, secretKey string, appKey []byte) error {
	accessEnc, err := crypto.EncryptPSK(accessKey, appKey)
	if err != nil {
		return err
	}
	secretEnc, err := crypto.EncryptPSK(secretKey, appKey)
	if err != nil {
		return err
	}
	_, err = d.db.Exec(`
		UPDATE dr_config SET
			s3_endpoint = ?, s3_bucket = ?, s3_region = ?,
			s3_access_key_enc = ?, s3_secret_key_enc = ?,
			config_version = config_version + 1
		WHERE id = 1`,
		endpoint, bucket, region, accessEnc, secretEnc)
	return err
}

// SaveDRServerConfig saves server backup restic password and retention.
func (d *DB) SaveDRServerConfig(resticPassword string, keepLast, keepDaily uint32, appKey []byte) error {
	enc, err := crypto.EncryptPSK(resticPassword, appKey)
	if err != nil {
		return err
	}
	_, err = d.db.Exec(`
		UPDATE dr_config SET
			server_restic_password_enc = ?,
			server_keep_last = ?, server_keep_daily = ?
		WHERE id = 1`, enc, keepLast, keepDaily)
	return err
}

// SaveDRNodeConfig saves node backup restic password, interval, and retention. Bumps config_version.
func (d *DB) SaveDRNodeConfig(resticPassword string, intervalHours, keepLast, keepDaily uint32, appKey []byte) error {
	enc, err := crypto.EncryptPSK(resticPassword, appKey)
	if err != nil {
		return err
	}
	_, err = d.db.Exec(`
		UPDATE dr_config SET
			restic_password_enc = ?,
			default_interval_hours = ?,
			node_keep_last = ?, node_keep_daily = ?,
			config_version = config_version + 1
		WHERE id = 1`, enc, intervalHours, keepLast, keepDaily)
	return err
}

// UpdateNodeDRStatus persists the DR status reported by a node's heartbeat.
func (d *DB) UpdateNodeDRStatus(nodeID uint64, s *models.DRStatus) error {
	var lastBackup *time.Time
	if s.LastBackupAt != "" {
		if t, err := time.Parse(time.RFC3339, s.LastBackupAt); err == nil {
			lastBackup = &t
		}
	}
	_, err := d.db.Exec(`
		UPDATE nodes SET
			dr_last_backup_at = ?, dr_last_status = ?, dr_last_error = ?,
			dr_snapshot_count = ?, dr_config_version = ?
		WHERE id = ?`,
		lastBackup, s.Status, s.Error,
		s.SnapshotCount, s.ConfigVersion,
		nodeID)
	return err
}

// SetNodeDREnabled sets the dr_enabled flag on a node.
func (d *DB) SetNodeDREnabled(nodeID uint64, enabled bool) error {
	_, err := d.db.Exec("UPDATE nodes SET dr_enabled = ? WHERE id = ?", enabled, nodeID)
	return err
}

// SetNodeDRForceRun sets the dr_force_run flag so the next heartbeat response triggers a DR run.
func (d *DB) SetNodeDRForceRun(nodeID uint64) error {
	_, err := d.db.Exec("UPDATE nodes SET dr_force_run = 1 WHERE id = ?", nodeID)
	return err
}

// ClearNodeDRForceRun clears the force_run flag after the CLI has reported a result.
func (d *DB) ClearNodeDRForceRun(nodeID uint64) error {
	_, err := d.db.Exec("UPDATE nodes SET dr_force_run = 0 WHERE id = ?", nodeID)
	return err
}

// UpdateServerBackupStatus records the result of an automatic server backup.
func (d *DB) UpdateServerBackupStatus(status, lastError string) error {
	_, err := d.db.Exec(`UPDATE server_tuning SET
		server_backup_last_at = NOW(),
		server_backup_last_status = ?,
		server_backup_last_error = ?
		WHERE id = 1`, status, lastError)
	return err
}

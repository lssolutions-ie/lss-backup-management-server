package db

import (
	"time"

	"github.com/lssolutions-ie/lss-management-server/internal/crypto"
	"github.com/lssolutions-ie/lss-management-server/internal/models"
)

// GetDRConfig reads the single-row DR configuration and decrypts secret fields.
func (d *DB) GetDRConfig(appKey []byte) (*models.DRConfig, error) {
	var cfg models.DRConfig
	var accessEnc, secretEnc, resticEnc string
	err := d.db.QueryRow(`
		SELECT s3_endpoint, s3_bucket, s3_region,
		       s3_access_key_enc, s3_secret_key_enc, restic_password_enc,
		       default_interval_hours, config_version
		FROM dr_config WHERE id = 1`).
		Scan(&cfg.S3Endpoint, &cfg.S3Bucket, &cfg.S3Region,
			&accessEnc, &secretEnc, &resticEnc,
			&cfg.DefaultIntervalHours, &cfg.ConfigVersion)
	if err != nil {
		return nil, err
	}

	// Decrypt secret fields. Empty encrypted values stay empty (not yet configured).
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

package storage

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

func RunMigrations(ctx context.Context, db *pgxpool.Pool) error {
	if _, err := db.Exec(ctx, CreateImageTableSQL); err != nil {
		return fmt.Errorf("creating image table: %w", err)
	}
	if _, err := db.Exec(ctx, CreateSBOMTableSQL); err != nil {
		return fmt.Errorf("creating sbom table: %w", err)
	}
	if _, err := db.Exec(ctx, CreateVulnerabilityReportTableSQL); err != nil {
		return fmt.Errorf("creating vulnerability report table: %w", err)
	}

	return nil
}

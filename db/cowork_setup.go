package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
)

// MutateCoworkSetup commits one task-setup change and its Cowork activity row
// together. The caller receives both stable IDs and may publish the activity
// only after this method returns successfully.
func (s *ExplorationStore) MutateCoworkSetup(activity Activity, mutate func(*sql.Tx, *Activity) (int64, error)) (entityID int64, saved Activity, activityID int64, err error) {
	if s == nil || s.db == nil || s.expID <= 0 {
		return 0, Activity{}, 0, fmt.Errorf("exploration store unavailable")
	}
	if activity.Worker != "cowork" || activity.Kind == "" || activity.Tool == "" || mutate == nil {
		return 0, Activity{}, 0, fmt.Errorf("invalid Cowork setup mutation")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return 0, Activity{}, 0, err
	}
	defer tx.Rollback() //nolint:errcheck
	entityID, err = mutate(tx, &activity)
	if err != nil {
		return 0, Activity{}, 0, err
	}
	if activity.ToolUseID == "" {
		return 0, Activity{}, 0, fmt.Errorf("Cowork setup activity key is required")
	}
	activityID, err = appendActivityTx(tx, s.expID, activity)
	if err != nil {
		return 0, Activity{}, 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, Activity{}, 0, err
	}
	activity.ID = activityID
	return entityID, activity, activityID, nil
}

// MutateCoworkScope commits a task-scope change and its activity entry in one
// transaction. It holds the same scope-mutation lock used by native asset writes.
func (s *AssetStore) MutateCoworkScope(explorationID int64, activity Activity, mutate func(*AssetStore, *Activity) (int64, error)) (entityID int64, saved Activity, activityID int64, err error) {
	if s == nil || s.db == nil || explorationID <= 0 || activity.Worker != "cowork" || activity.Kind == "" || activity.Tool == "" || mutate == nil {
		return 0, Activity{}, 0, fmt.Errorf("invalid Cowork scope mutation")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return 0, Activity{}, 0, err
	}
	defer tx.Rollback() //nolint:errcheck
	if err := lockCompanyScopeMutation(tx); err != nil {
		return 0, Activity{}, 0, err
	}
	scoped := &AssetStore{db: s.db, company: s.company, tx: tx}
	entityID, err = mutate(scoped, &activity)
	if err != nil {
		return 0, Activity{}, 0, err
	}
	if activity.ToolUseID == "" {
		return 0, Activity{}, 0, fmt.Errorf("Cowork scope activity key is required")
	}
	activityID, err = appendActivityTx(tx, explorationID, activity)
	if err != nil {
		return 0, Activity{}, 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, Activity{}, 0, err
	}
	activity.ID = activityID
	return entityID, activity, activityID, nil
}

func appendActivityTx(tx *sql.Tx, explorationID int64, activity Activity) (int64, error) {
	metadata := activity.Metadata
	if len(metadata) == 0 {
		metadata = json.RawMessage(`{}`)
	}
	var activityID int64
	err := tx.QueryRow(`
INSERT INTO activity(exploration_id, node_id, worker, kind, tool, tool_use_id, is_error, summary, detail, metadata, input_tokens, output_tokens, cache_read_tokens, cache_write_tokens, main_seg)
VALUES ($1,$2,NULLIF($3,''),NULLIF($4,''),NULLIF($5,''),NULLIF($6,''),$7,NULLIF($8,''),NULLIF($9,''),$10,$11,$12,$13,$14,$15)
RETURNING id`, explorationID, activity.NodeID, utf8Clean(activity.Worker), utf8Clean(activity.Kind), utf8Clean(activity.Tool), utf8Clean(activity.ToolUseID), activity.IsError, utf8Clean(activity.Summary), utf8Clean(activity.Detail), metadata, activity.InputTokens, activity.OutputTokens, activity.CacheReadTokens, activity.CacheWriteTokens, activity.MainSeg).Scan(&activityID)
	return activityID, err
}

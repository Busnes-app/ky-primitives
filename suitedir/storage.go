package suitedir

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
)

// StorageReport is one app's actual committed usage and requested additional reservation.
// Seq is a strictly increasing value from the app's shared DB, never a replica clock.
// Contract: KyIdentity's POST /api/suite/storage, docs/SUITE-DIRECTORY.md.
type StorageReport struct {
	OrgID     string `json:"org_id"`
	UsedBytes int64  `json:"used_bytes"`
	Seq       int64  `json:"seq"`
	WantBytes int64  `json:"want_bytes"`
}

// StorageResult answers exactly one report. Unknown orgs carry no grant. On stale,
// the app retains its existing grant until expiry and needs operator sequence recovery.
// Grant expiry starts when the app sent the request, never at response arrival.
type StorageResult struct {
	OrgID                                                  string
	Result                                                 string // ok, stale, unknown_org
	Seq, CeilingBytes, TTLSeconds, PoolBytes, OrgUsedBytes int64
	OverSince                                              *int64
}

var ErrStorageRequest = errors.New("suitedir: storage: invalid reports")
var ErrStorageAnswer = errors.New("suitedir: storage: malformed answer")

// ReportStorage validates the entire request and answer, returning no partial result on
// any malformed/missing/duplicate entry. It makes one bounded, authenticated POST without
// redirects or automatic retry. The caller owns batching, durable sequence/usage snapshots,
// retries with the same sequence and bytes, local grant admission, and renewal scheduling.
func (c *Client) ReportStorage(ctx context.Context, reports []StorageReport) ([]StorageResult, error) {
	if len(reports) < 1 || len(reports) > 500 {
		return nil, ErrStorageRequest
	}
	requested := make(map[string]StorageReport, len(reports))
	for _, r := range reports {
		if !erasedOrg.MatchString(r.OrgID) || r.Seq <= 0 || r.UsedBytes < 0 || r.UsedBytes > 1<<53 || r.WantBytes < 0 || r.WantBytes > 1<<53 {
			return nil, ErrStorageRequest
		}
		if _, ok := requested[r.OrgID]; ok {
			return nil, ErrStorageRequest
		}
		requested[r.OrgID] = r
	}
	raw, err := json.Marshal(struct {
		Reports []StorageReport `json:"reports"`
	}{reports})
	if err != nil {
		return nil, err
	}
	if len(raw) > 64<<10 {
		return nil, ErrStorageRequest
	}
	var answer struct {
		Results []storageResult `json:"results"`
	}
	if err := c.request(ctx, http.MethodPost, "storage", nil, raw, maxBody, &answer); err != nil {
		return nil, err
	}
	if len(answer.Results) != len(reports) {
		return nil, ErrStorageAnswer
	}
	out := make([]StorageResult, 0, len(reports))
	for _, v := range answer.Results {
		r, ok := requested[v.OrgID]
		if !ok {
			return nil, ErrStorageAnswer
		}
		delete(requested, v.OrgID)
		result := StorageResult{OrgID: v.OrgID, Result: v.Result}
		if v.Result == "unknown_org" {
			if v.Seq != nil || v.Ceiling != nil || v.TTL != nil || v.Pool != nil || v.Used != nil || v.OverSince != nil {
				return nil, ErrStorageAnswer
			}
		} else {
			if (v.Result != "ok" && v.Result != "stale") || v.Seq == nil || v.Ceiling == nil || v.TTL == nil || v.Pool == nil || v.Used == nil {
				return nil, ErrStorageAnswer
			}
			if *v.Seq <= 0 || *v.Ceiling < 0 || *v.TTL <= 0 || *v.TTL > 900 || *v.Pool < 0 || *v.Used < 0 || v.OverSince != nil && *v.OverSince <= 0 {
				return nil, ErrStorageAnswer
			}
			if v.Result == "ok" && (*v.Seq != r.Seq || *v.Ceiling < r.UsedBytes || *v.Ceiling-r.UsedBytes > r.WantBytes) {
				return nil, ErrStorageAnswer
			}
			if v.Result == "stale" && *v.Seq < r.Seq {
				return nil, ErrStorageAnswer
			}
			result.Seq, result.CeilingBytes, result.TTLSeconds, result.PoolBytes, result.OrgUsedBytes, result.OverSince = *v.Seq, *v.Ceiling, *v.TTL, *v.Pool, *v.Used, v.OverSince
		}
		out = append(out, result)
	}
	return out, nil
}

type storageResult struct {
	OrgID     string `json:"org_id"`
	Result    string `json:"result"`
	Seq       *int64 `json:"seq"`
	Ceiling   *int64 `json:"ceiling_bytes"`
	TTL       *int64 `json:"ttl_seconds"`
	Pool      *int64 `json:"pool_bytes"`
	Used      *int64 `json:"org_used_bytes"`
	OverSince *int64 `json:"over_since"`
}

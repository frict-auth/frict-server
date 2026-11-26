package server

import (
	"net/http"
	"strconv"
)

// AppVersionHeader carries the app's Android versionCode on every device
// request. It is not signed: it decides only whether to ask for an update.
const AppVersionHeader = "Frict-App-Version"

// MaxAppVersion is the largest versionCode Google Play accepts.
const MaxAppVersion = 2100000000

// appVersion is r's versionCode, or 0 with why there is none: "missing" or
// "malformed".
func appVersion(r *http.Request) (int, string) {
	vs := r.Header.Values(AppVersionHeader)
	if len(vs) == 0 {
		return 0, "missing"
	}
	v, err := strconv.Atoi(vs[0])
	if len(vs) > 1 || err != nil || v < 1 || v > MaxAppVersion || vs[0] != strconv.Itoa(v) {
		return 0, "malformed"
	}
	return v, ""
}

// appCurrent answers 426 and returns false when a minimum app version is set
// and version, read from r with appVersion, is below it.
func (s *Server) appCurrent(w http.ResponseWriter, r *http.Request, userID string, version int, reason string) bool {
	if version >= s.minAppVersion {
		return true
	}
	if reason == "" {
		reason = "below_minimum"
	}
	s.log.Warn("app update required", "endpoint", r.URL.Path, "reason", reason, "app_version", version,
		"min_app_version", s.minAppVersion, "user_id", userID)
	writeJSON(w, http.StatusUpgradeRequired, map[string]any{"error": "app_update_required", "min_version": s.minAppVersion})
	return false
}

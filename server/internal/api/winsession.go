package api

import (
	"net/http"
	"strings"

	"securetunnel/server/internal/model"
)

// windowsPolicy is the group's Windows session behavior with defaults filled.
func windowsPolicy(g model.PolicyGroup) model.WindowsSessionPolicy {
	p := g.Windows
	if err := p.Normalize(); err != nil {
		return model.DefaultWindowsSessions()
	}
	return p
}

// windowsUserOK applies the group's "Windows user doesn't match" rule. The app
// reports the Windows user it was started from (UPN, or DOMAIN\user).
func (s *Server) windowsUserOK(w http.ResponseWriter, r *http.Request, upn string, b connectBody, group model.PolicyGroup) bool {
	pol := windowsPolicy(group)
	if b.WindowsUser == "" || pol.UserMatch == model.WinAllow || model.WindowsUserMatches(b.WindowsUser, upn) {
		return true
	}
	detail := "Windows user " + b.WindowsUser + " signed in to the VPN as " + upn + " (sign-in policy " + group.Name + ")"
	if pol.UserMatch == model.WinWarn {
		_ = s.Store.AddAudit(r.Context(), model.AuditEntry{At: s.now(), Actor: strings.ToLower(upn),
			Action: "vpn.windows_user_mismatch", Detail: detail})
		return true
	}
	_ = s.Store.AddAudit(r.Context(), model.AuditEntry{At: s.now(), Actor: strings.ToLower(upn),
		Action: "vpn.windows_user_blocked", Detail: detail})
	writeErr(w, http.StatusForbidden, "windows_user_mismatch",
		"You're signed in to Windows as "+b.WindowsUser+", so you have to sign in to the VPN with that same account.")
	return false
}

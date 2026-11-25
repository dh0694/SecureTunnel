package devicetrust

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode/utf16"
)

// Graph reads Entra device objects with the app's own identity (client
// credentials). The app registration needs the Microsoft Graph application
// permission Device.Read.All, with admin consent.
type Graph struct {
	// Creds returns the tenant, client ID and client secret ("" = not set up).
	Creds func(ctx context.Context) (tenant, client, secret string)
	HTTP  *http.Client

	mu       sync.Mutex
	token    string
	tokenFor string
	tokenExp time.Time
	cache    map[string]graphCached
}

type graphCached struct {
	dev *GraphDevice
	err error
	at  time.Time
}

// GraphDevice is the part of an Entra device object we use.
type GraphDevice struct {
	ObjectID       string `json:"id"`
	DeviceID       string `json:"deviceId"`
	DisplayName    string `json:"displayName"`
	AccountEnabled *bool  `json:"accountEnabled"`
	IsCompliant    *bool  `json:"isCompliant"`
	IsManaged      *bool  `json:"isManaged"`
	TrustType      string `json:"trustType"` // AzureAd, ServerAd (hybrid), Workplace (registered)
	OS             string `json:"operatingSystem"`
	OSVersion      string `json:"operatingSystemVersion"`
	AltSecIDs      []struct {
		Type int    `json:"type"`
		Key  string `json:"key"`
	} `json:"alternativeSecurityIds"`
}

// ErrGraphNotSetUp means Entra sign-in (with a client secret) isn't configured.
var ErrGraphNotSetUp = errors.New("Microsoft Graph isn't set up (needs Entra sign-in with a client secret)")

func (g *Graph) client() *http.Client {
	if g.HTTP != nil {
		return g.HTTP
	}
	return &http.Client{Timeout: 15 * time.Second}
}

func (g *Graph) accessToken(ctx context.Context) (string, error) {
	tenant, client, secret := "", "", ""
	if g.Creds != nil {
		tenant, client, secret = g.Creds(ctx)
	}
	if tenant == "" || client == "" || secret == "" {
		return "", ErrGraphNotSetUp
	}
	key := tenant + "|" + client + "|" + secret
	g.mu.Lock()
	if g.token != "" && g.tokenFor == key && time.Until(g.tokenExp) > 2*time.Minute {
		t := g.token
		g.mu.Unlock()
		return t, nil
	}
	g.mu.Unlock()

	form := url.Values{
		"client_id":     {client},
		"client_secret": {secret},
		"grant_type":    {"client_credentials"},
		"scope":         {"https://graph.microsoft.com/.default"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://login.microsoftonline.com/"+tenant+"/oauth2/v2.0/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := g.client().Do(req)
	if err != nil {
		return "", fmt.Errorf("Microsoft sign-in for Graph: %w", err)
	}
	defer resp.Body.Close()
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		Error       string `json:"error"`
		Desc        string `json:"error_description"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return "", fmt.Errorf("Graph token response: %w", err)
	}
	if out.AccessToken == "" {
		d := out.Desc
		if i := strings.IndexAny(d, "\r\n"); i > 0 {
			d = d[:i]
		}
		return "", fmt.Errorf("Graph token: %s %s", out.Error, d)
	}
	g.mu.Lock()
	g.token, g.tokenFor = out.AccessToken, key
	g.tokenExp = time.Now().Add(time.Duration(out.ExpiresIn) * time.Second)
	g.mu.Unlock()
	return out.AccessToken, nil
}

func (g *Graph) get(ctx context.Context, path string, out any) error {
	return g.getWith(ctx, path, nil, out)
}

func (g *Graph) getWith(ctx context.Context, path string, headers map[string]string, out any) error {
	tok, err := g.accessToken(ctx)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://graph.microsoft.com/v1.0"+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := g.client().Do(req)
	if err != nil {
		return fmt.Errorf("Microsoft Graph: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		_ = json.Unmarshal(body, &e)
		if resp.StatusCode == http.StatusForbidden || e.Error.Code == "Authorization_RequestDenied" {
			return errors.New("Microsoft Graph denied access: grant the app the Device.Read.All and GroupMember.Read.All application permissions, with admin consent")
		}
		return fmt.Errorf("Microsoft Graph %d: %s %s", resp.StatusCode, e.Error.Code, e.Error.Message)
	}
	return json.Unmarshal(body, out)
}

// Device looks up an Entra device by its device ID (cached for 2 minutes).
// It returns (nil, nil) when Entra has no such device.
func (g *Graph) Device(ctx context.Context, deviceID string) (*GraphDevice, error) {
	deviceID = strings.ToLower(strings.TrimSpace(deviceID))
	if !guidLike(deviceID) {
		return nil, errors.New("not a device ID")
	}
	g.mu.Lock()
	if c, ok := g.cache[deviceID]; ok && time.Since(c.at) < 2*time.Minute {
		g.mu.Unlock()
		return c.dev, c.err
	}
	g.mu.Unlock()

	var out struct {
		Value []GraphDevice `json:"value"`
	}
	q := url.Values{
		"$filter": {"deviceId eq '" + deviceID + "'"},
		"$select": {"id,deviceId,displayName,accountEnabled,isCompliant,isManaged,trustType,operatingSystem,operatingSystemVersion,alternativeSecurityIds"},
	}
	err := g.get(ctx, "/devices?"+q.Encode(), &out)
	var dev *GraphDevice
	if err == nil && len(out.Value) > 0 {
		dev = &out.Value[0]
	}
	g.mu.Lock()
	if g.cache == nil || len(g.cache) > 20000 {
		g.cache = map[string]graphCached{}
	}
	g.cache[deviceID] = graphCached{dev: dev, err: err, at: time.Now()}
	g.mu.Unlock()
	return dev, err
}

// Probe checks that Graph works (token + permission), for the admin site.
func (g *Graph) Probe(ctx context.Context) error {
	var out struct {
		Value []GraphDevice `json:"value"`
	}
	return g.get(ctx, "/devices?$top=1&$select=id", &out)
}

// KeyMatches reports whether a certificate (SHA-1 thumbprint, hex) is the
// device's registered key. Entra stores it in alternativeSecurityIds as a
// UTF-16 string "X509:<SHA1-TP-PUBKEY>{thumbprint}{public key hash}".
// ok is false when Graph returned no keys to compare.
func (d *GraphDevice) KeyMatches(thumbprint string) (match, ok bool) {
	thumbprint = strings.ToUpper(thumbprint)
	for _, a := range d.AltSecIDs {
		raw, err := base64.StdEncoding.DecodeString(a.Key)
		if err != nil {
			continue
		}
		ok = true
		if strings.Contains(strings.ToUpper(decodeUTF16(raw)), thumbprint) || strings.Contains(strings.ToUpper(string(raw)), thumbprint) {
			return true, true
		}
	}
	return false, ok
}

func decodeUTF16(b []byte) string {
	if len(b)%2 == 1 {
		b = b[:len(b)-1]
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = uint16(b[2*i]) | uint16(b[2*i+1])<<8
	}
	return string(utf16.Decode(u))
}

func guidLike(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
				return false
			}
		}
	}
	return true
}

type memberCached struct {
	ids []string
	err error
	at  time.Time
}

var (
	memberMu    sync.Mutex
	memberCache = map[string]memberCached{}
)

// MemberGroups returns the IDs of the Entra groups a user belongs to,
// directly or nested (cached for 5 minutes). Needs GroupMember.Read.All.
func (g *Graph) MemberGroups(ctx context.Context, userOID string) ([]string, error) {
	userOID = strings.ToLower(strings.TrimSpace(userOID))
	if !guidLike(userOID) {
		return nil, errors.New("not an Entra user ID")
	}
	memberMu.Lock()
	if c, ok := memberCache[userOID]; ok && time.Since(c.at) < 5*time.Minute {
		memberMu.Unlock()
		return c.ids, c.err
	}
	memberMu.Unlock()

	var ids []string
	path := "/users/" + userOID + "/transitiveMemberOf/microsoft.graph.group?$select=id&$top=999"
	var err error
	for page := 0; page < 20 && path != ""; page++ {
		var out struct {
			Value []struct {
				ID string `json:"id"`
			} `json:"value"`
			Next string `json:"@odata.nextLink"`
		}
		if err = g.get(ctx, path, &out); err != nil {
			ids = nil
			break
		}
		for _, v := range out.Value {
			ids = append(ids, strings.ToLower(v.ID))
		}
		path = strings.TrimPrefix(out.Next, "https://graph.microsoft.com/v1.0")
	}
	memberMu.Lock()
	if len(memberCache) > 20000 {
		memberCache = map[string]memberCached{}
	}
	memberCache[userOID] = memberCached{ids: ids, err: err, at: time.Now()}
	memberMu.Unlock()
	return ids, err
}

// GroupRef is an Entra group found by SearchGroups.
type GroupRef struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// SearchGroups finds security groups whose name starts with q (for the admin site).
func (g *Graph) SearchGroups(ctx context.Context, q string) ([]GroupRef, error) {
	q = strings.TrimSpace(q)
	if len(q) > 100 {
		q = q[:100]
	}
	filter := "securityEnabled eq true"
	if q != "" {
		filter = "startswith(displayName,'" + strings.ReplaceAll(q, "'", "''") + "') and " + filter
	}
	v := url.Values{"$filter": {filter}, "$select": {"id,displayName,description"}, "$top": {"25"}, "$orderby": {"displayName"}, "$count": {"true"}}
	var out struct {
		Value []struct {
			ID          string `json:"id"`
			DisplayName string `json:"displayName"`
			Description string `json:"description"`
		} `json:"value"`
	}
	// $orderby with $filter needs the advanced query header.
	if err := g.getWith(ctx, "/groups?"+v.Encode(), map[string]string{"ConsistencyLevel": "eventual"}, &out); err != nil {
		return nil, err
	}
	res := []GroupRef{}
	for _, x := range out.Value {
		res = append(res, GroupRef{ID: strings.ToLower(x.ID), Name: x.DisplayName, Description: x.Description})
	}
	return res, nil
}

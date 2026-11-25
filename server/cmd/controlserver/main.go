// Command controlserver runs the SecureTunnel control plane and admin website.
//
// Subcommands:
//
//	controlserver                    run the server
//	controlserver gateway-token      print a new gateway API token and its hash
//	controlserver useradd NAME ROLE  create a local account (password from ST_NEW_PASSWORD)
package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"securetunnel/server/internal/admin"
	"securetunnel/server/internal/api"
	"securetunnel/server/internal/config"
	"securetunnel/server/internal/downloads"
	"securetunnel/server/internal/hostmetrics"
	"securetunnel/server/internal/devicetrust"
	"securetunnel/server/internal/duo"
	"securetunnel/server/internal/policies"
	"securetunnel/server/internal/lbstats"
	"securetunnel/server/internal/localauth"
	"securetunnel/server/internal/signin"
	"securetunnel/server/internal/model"
	"securetunnel/server/internal/session"
	"securetunnel/server/internal/store"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if len(os.Args) > 1 {
		if err := subcommand(os.Args[1:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if err := run(log); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func subcommand(args []string) error {
	switch args[0] {
	case "gateway-token":
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return err
		}
		tok := hex.EncodeToString(b)
		fmt.Printf("token=%s\nhash=%s\n", tok, session.HashGatewayToken(tok))
		return nil
	case "useradd":
		if len(args) != 3 {
			return errors.New("usage: controlserver useradd NAME ROLE   (password in ST_NEW_PASSWORD)")
		}
		cfg, err := config.Load()
		if err != nil {
			return err
		}
		if cfg.DatabaseURL == "" {
			return errors.New("useradd needs ST_DATABASE_URL")
		}
		ctx := context.Background()
		pg, err := store.OpenPostgres(ctx, cfg.DatabaseURL)
		if err != nil {
			return err
		}
		defer pg.Close()
		return createUser(ctx, pg, args[1], args[2], os.Getenv("ST_NEW_PASSWORD"))
	}
	return fmt.Errorf("unknown command %q", args[0])
}

func createUser(ctx context.Context, st store.Store, name, role, password string) error {
	if !model.ValidRole(role) {
		return errors.New("role must be admin, helpdesk or user")
	}
	hash, err := localauth.HashPassword(password)
	if err != nil {
		return err
	}
	return st.CreateUser(ctx, model.User{Username: name, DisplayName: name, PasswordHash: hash, Role: role, CreatedAt: time.Now()})
}

func run(log *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if len(cfg.SecretKey) == 0 {
		cfg.SecretKey = make([]byte, 32)
		_, _ = rand.Read(cfg.SecretKey)
		log.Warn("ST_SECRET_KEY not set: using a random key; admin sign-ins end on restart (dev only)")
	}

	var st store.Store
	var ping func(context.Context) error
	if cfg.DatabaseURL != "" {
		var pg *store.Postgres
		for attempt := 1; ; attempt++ { // the database container may still be starting
			pg, err = store.OpenPostgres(ctx, cfg.DatabaseURL)
			if err == nil || attempt == 30 || ctx.Err() != nil {
				break
			}
			log.Info("waiting for database", "attempt", attempt, "err", err)
			time.Sleep(2 * time.Second)
		}
		if err != nil {
			return err
		}
		defer pg.Close()
		st, ping = pg, pg.Ping
	} else {
		log.Warn("using in-memory store: development only, not HA, state is lost on restart")
		st = store.NewMemory()
	}

	if cfg.GatewaysFile != "" {
		if err := seedGateways(ctx, st, cfg.GatewaysFile); err != nil {
			return fmt.Errorf("gateways file: %w", err)
		}
	}
	if err := bootstrapAdmin(ctx, st, cfg, log); err != nil {
		return err
	}

	localAuth := &localauth.Authenticator{
		Store:       st,
		TokenKey:    localauth.DeriveKey(cfg.SecretKey, "vpn-connect-token"),
		TokenTTL:    5 * time.Minute,
		RequireTOTP: cfg.LocalRequireTOTP,
	}
	signIn := &signin.Manager{
		Store:           st,
		Defaults:        signin.DefaultsFromEnv(cfg.LocalAuth, cfg.TenantID, cfg.Audiences, cfg.EntraSecret),
		Local:           localAuth,
		RequireMFA:      cfg.RequireMFAClaim,
		MaxAuthAge:      cfg.MaxAuthAge,
		RequireAuthTime: cfg.RequireAuthTime,
		Log:             log,
	}
	trust := &devicetrust.Checker{
		Store: st,
		Key:   localauth.DeriveKey(cfg.SecretKey, "device-proof"),
		Graph: &devicetrust.Graph{Creds: func(ctx context.Context) (string, string, string) {
			s := signIn.Get(ctx)
			if !s.EntraReady() {
				return "", "", ""
			}
			return s.TenantID, s.ClientID, s.ClientSecret
		}},
	}
	groups := &policies.Manager{Store: st, Trust: trust, Graph: trust.Graph}
	trust.CertWants = groups.CertWants
	duoSvc := &duo.Service{Store: st, Key: localauth.DeriveKey(cfg.SecretKey, "duo-tx")}
	cur := signIn.Get(ctx)
	log.Info("sign-in methods", "local_accounts", cur.LocalEnabled, "local_require_totp", cfg.LocalRequireTOTP, "entra", cur.EntraReady())
	sessions := session.New(st, session.Config{
		Grace:            cfg.Grace,
		SuspendAfter:     cfg.SuspendAfter,
		Heartbeat:        cfg.Heartbeat,
		MaxLifetime:      cfg.MaxLifetime,
		GatewayHealthTTL: cfg.GatewayHealthTTL,
		DefaultPolicy: model.PlacementPolicy{
			MaxCPUPercent: cfg.PlaceMaxCPU, MaxMemPercent: cfg.PlaceMaxMem, MinFreeDiskGB: cfg.PlaceMinDiskGB,
		},
	}, nil, log)
	sessions.ApprovalFor = func(ctx context.Context, d model.Device) (model.DevicePolicy, bool) {
		p, _ := groups.ForDevice(ctx, model.PolicyApproval, d.Platform, d.Name)
		if p.Approval == nil {
			return model.DevicePolicy{}, false
		}
		return *p.Approval, true
	}
	sessions.CountryFor = func(ctx context.Context, id model.Identity, platform, deviceName string) (model.CountryPolicy, error) {
		p, err := groups.ForUser(ctx, model.PolicyCountries, id, platform, deviceName)
		if err != nil {
			return model.CountryPolicy{}, err
		}
		return *p.Countries, nil
	}
	if err := sessions.Config().DefaultPolicy.Validate(); err != nil {
		return fmt.Errorf("placement defaults (ST_PLACE_*): %w", err)
	}

	// Host metrics: ~15 minutes of history at one sample per 15 s.
	history := hostmetrics.NewHistory(60)
	hostLabel := os.Getenv("ST_HOST_LABEL")
	if hostLabel == "" {
		hostLabel, _ = os.Hostname()
	}
	go metricsLoop(ctx, history, hostLabel, st, log)

	mux := http.NewServeMux()
	clientAPI := &api.Server{
		History:  history,
		Tokens:   signIn,
		SignIn:   signIn,
		Trust:    trust,
		Groups:   groups,
		Duo:      duoSvc,
		Sessions: sessions,
		Store:    st,
		Tunnel:   api.TunnelDefaults{DNS: cfg.DNS, AllowedIPs: cfg.AllowedIPs, MTU: cfg.MTU, Keepalive: cfg.Keepalive},
		Ping:     ping,
		Log:      log,
	}
	clientAPI.LocalAuth = localAuth // on/off follows the sign-in settings
	clientAPI.Register(mux)
	adminSrv := &admin.Server{
		History:      history,
		Store:        st,
		Sessions:     sessions,
		Auth:         localAuth,
		SignIn:       signIn,
		Trust:        trust,
		HostLabel:    hostLabel,
		Groups:       groups,
		Duo:          duoSvc,
		PublicURL:    cfg.PublicURL,
		CookieKey:    localauth.DeriveKey(cfg.SecretKey, "admin-cookie"),
		SecureCookie: cfg.TLSCert != "",
		HealthTTL:    cfg.GatewayHealthTTL,
		Log:          log,
	}
	if sizer, ok := st.(interface {
		DatabaseSize(context.Context) (int64, error)
	}); ok {
		adminSrv.DBSize = sizer.DatabaseSize
	}
	if pg, ok := st.(*store.Postgres); ok {
		adminSrv.DBStats = func(ctx context.Context) (any, error) { return pg.DatabaseStats(ctx) }
	}
	if u := os.Getenv("ST_LB_STATS_URL"); u != "" { // set in the HA lab
		adminSrv.LBStats = func(ctx context.Context) (any, error) { return lbstats.Fetch(ctx, u) }
	}
	dl := &downloads.Handler{Dir: cfg.DownloadsDir, PublicURL: cfg.PublicURL, Log: log}
	adminSrv.LatestClient = dl.LatestVersion
	dl.Offer = adminSrv.UpdateOffer // pause, staged rollout and install policy (App updates page)
	adminSrv.Register(mux)
	dl.Register(mux)

	go sweepLoop(ctx, sessions, cfg.SweepInterval, log)

	httpSrv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
	}
	errc := make(chan error, 1)
	go func() {
		log.Info("control server listening", "addr", cfg.Listen, "tls", cfg.TLSCert != "", "admin", "/admin/")
		if cfg.TLSCert != "" {
			errc <- httpSrv.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey)
		} else {
			errc <- httpSrv.ListenAndServe()
		}
	}()

	select {
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
		log.Info("shutting down")
		shutCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return httpSrv.Shutdown(shutCtx)
	}
	return nil
}

// bootstrapAdmin creates the first admin account when the user table is empty.
func bootstrapAdmin(ctx context.Context, st store.Store, cfg config.Config, log *slog.Logger) error {
	if cfg.BootstrapAdminPass == "" {
		return nil
	}
	n, err := st.CountUsers(ctx)
	if err != nil || n > 0 {
		return err
	}
	if err := createUser(ctx, st, cfg.BootstrapAdminUser, model.RoleAdmin, cfg.BootstrapAdminPass); err != nil {
		return fmt.Errorf("bootstrap admin: %w", err)
	}
	log.Info("created bootstrap admin account", "username", cfg.BootstrapAdminUser)
	return nil
}

// metricsLoop samples this control server every 15 s, keeps local history
// and reports to the database so every control server's admin site can show
// all of them (and which are up).
func metricsLoop(ctx context.Context, h *hostmetrics.History, label string, st store.Store, log *slog.Logger) {
	s := &hostmetrics.Sampler{DiskPath: "/", Label: label}
	s.Sample() // prime the CPU counters
	record := func() {
		m := s.Sample()
		h.Add("control", m)
		if err := st.SetControlHost(ctx, label, m, time.Now()); err != nil {
			log.Warn("report control host", "err", err)
		}
	}
	select {
	case <-ctx.Done():
		return
	case <-time.After(2 * time.Second):
		record()
	}
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			record()
		}
	}
}

func sweepLoop(ctx context.Context, s *session.Service, every time.Duration, log *slog.Logger) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r, err := s.Sweep(ctx)
			if err != nil {
				log.Error("sweep failed", "err", err)
				continue
			}
			if r.Suspended+r.Expired+r.Terminated > 0 {
				log.Info("sweep", "suspended", r.Suspended, "expired", r.Expired, "terminated", r.Terminated)
			}
		}
	}
}

func seedGateways(ctx context.Context, st store.Store, path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var gws []model.Gateway
	if err := json.Unmarshal(b, &gws); err != nil {
		return err
	}
	for _, g := range gws {
		if err := st.UpsertGateway(ctx, g); err != nil {
			return err
		}
	}
	return nil
}

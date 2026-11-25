package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"time"

	"github.com/Microsoft/go-winio"

	"securetunnel/server/internal/agentcfg"
	"securetunnel/server/internal/agentcore"
	"securetunnel/server/internal/clientapi"
)

// The GUI (running as the signed-in user) talks to the service (SYSTEM) over
// a named pipe: one JSON request and one JSON response per connection.
// SYSTEM and Administrators get full access; interactive users can read and write.
const (
	pipeSDDL              = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)"
	authConfigPipeTimeout = 15 * time.Second // the server request itself can take 10 seconds
)

type ipcRequest struct {
	Cmd      string `json:"cmd"` // status | connect | disconnect | set_server | diagnose
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	Code     string `json:"code,omitempty"`
	Server   string `json:"server,omitempty"`
	ID       string `json:"id,omitempty"`
	Token    string `json:"token,omitempty"` // connect_token: Entra access token from the GUI's browser sign-in
	// Device trust from the GUI: the challenge it fetched and its user-certificate proof.
	Challenge *clientapi.Challenge    `json:"challenge,omitempty"`
	Proofs    []clientapi.DeviceProof `json:"proofs,omitempty"`

	caller winUser // set by the service from the pipe, never from the request
}

// extraFrom passes the GUI's challenge and user-certificate proof to the engine.
// Only user-certificate proofs come from the GUI; device proofs are made here.
func extraFrom(req ipcRequest) agentcore.ConnectExtra {
	x := agentcore.ConnectExtra{Challenge: req.Challenge, WindowsUser: req.caller.Name}
	for _, p := range req.Proofs {
		if p.Kind == "user_cert" {
			x.Proofs = append(x.Proofs, p)
		}
	}
	return x
}

type diagItem struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

type ipcResponse struct {
	OK        bool                  `json:"ok"`
	Error     string                `json:"error,omitempty"`
	ErrorCode string                `json:"error_code,omitempty"`
	Status    *agentcore.Status     `json:"status,omitempty"`
	Diag      []diagItem            `json:"diag,omitempty"`
	Update    *UpdateInfo           `json:"update,omitempty"`
	Speed     *SpeedInfo            `json:"speed,omitempty"`
	IPs       *IPInfo               `json:"ips,omitempty"`
	Notice    *Notice               `json:"notice,omitempty"`
	Auth      *clientapi.AuthConfig `json:"auth,omitempty"`
	LogRef    string                `json:"log_ref,omitempty"`
	Challenge *clientapi.Challenge  `json:"challenge,omitempty"`
	Certs     *certList             `json:"certs,omitempty"` // device certificates (cmd "certs")
	Owner     *ownerView            `json:"owner,omitempty"` // who connected the tunnel, from the caller's point of view
}

func listenPipe() (net.Listener, error) {
	return winio.ListenPipe(pipeName, &winio.PipeConfig{SecurityDescriptor: pipeSDDL, InputBufferSize: 64 << 10, OutputBufferSize: 64 << 10})
}

func servePipe(ln net.Listener, a *agentService) {
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, winio.ErrPipeListenerClosed) || errors.Is(err, net.ErrClosed) {
				return
			}
			a.log.Warn("pipe accept", "err", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		go a.handleConn(c)
	}
}

func (a *agentService) handleConn(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(200 * time.Second)) // connect may wait for a Duo Push
	var req ipcRequest
	if err := json.NewDecoder(c).Decode(&req); err != nil {
		return
	}
	// Who's asking: the Windows user in the caller's session decides who owns
	// the tunnel and what other users may do (see winsession_windows.go).
	req.caller = sessionUser(pipeCallerSession(c))
	if msg := a.checkCaller(req.Cmd, req.caller); msg != "" {
		st := a.engine.Status()
		_ = json.NewEncoder(c).Encode(ipcResponse{Error: msg, ErrorCode: "in_use", Status: &st, Owner: a.ownerViewFor(req.caller)})
		return
	}
	resp := a.handle(req)
	if resp.OK && (req.Cmd == "connect" || req.Cmd == "connect_token") {
		a.claim(req.caller)
	}
	if resp.Status != nil {
		resp.Owner = a.ownerViewFor(req.caller)
	}
	_ = json.NewEncoder(c).Encode(resp)
}

func (a *agentService) handle(req ipcRequest) ipcResponse {
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	e := a.engine
	errResp := func(err error) ipcResponse {
		r := ipcResponse{Error: agentcore.Friendly(err)}
		var ae *clientapi.APIError
		if errors.As(err, &ae) {
			r.ErrorCode = ae.Code
			if ae.Code == "code_required" {
				r.Error = "Enter the code from your authenticator app."
			}
		} else if err != nil && !errors.Is(err, agentcore.ErrBusy) {
			r.Error = err.Error()
			if f := agentcore.Friendly(err); f != "Couldn't connect: "+err.Error() {
				r.Error = f
			}
		}
		st := e.Status()
		r.Status = &st
		return r
	}
	switch req.Cmd {
	case "status":
	case "connect":
		if err := e.Connect(ctx, req.Username, req.Password, req.Code, extraFrom(req)); err != nil {
			return errResp(err)
		}
	case "connect_token":
		if err := e.ConnectWithToken(ctx, req.Username, req.Token, extraFrom(req)); err != nil {
			return errResp(err)
		}
	case "challenge":
		server, _ := configuredServer()
		if server == "" {
			return errResp(errors.New("no server is set up yet"))
		}
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		ch, err := a.client(server).Challenge(cctx)
		cancel()
		if err != nil {
			return errResp(err)
		}
		return ipcResponse{OK: true, Challenge: &ch}
	case "auth_config":
		server, _ := configuredServer()
		if server == "" {
			return errResp(errors.New("no server is set up yet"))
		}
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		cfg, err := a.client(server).AuthConfig(cctx)
		cancel()
		if clientapi.HasStatus(err, 404) {
			cfg, err = clientapi.AuthConfig{Local: true}, nil // older server
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return ipcResponse{Error: "The server didn't respond while checking sign-in options. Check your connection and try again."}
		}
		if err != nil {
			return errResp(err)
		}
		st := e.Status()
		return ipcResponse{OK: true, Status: &st, Auth: &cfg}
	case "disconnect":
		if err := e.Disconnect(ctx); err != nil {
			return errResp(err)
		}
	case "set_server":
		if _, locked := configuredServer(); locked {
			return errResp(errors.New("the server is set by your IT department"))
		}
		s, err := agentcfg.NormalizeServer(req.Server)
		if err != nil {
			return errResp(err)
		}
		if err := e.SetServer(s, false); err != nil {
			return errResp(err)
		}
		if err := saveServer(s); err != nil {
			return errResp(err)
		}
		a.log.Info("server changed", "server", s)
	case "diagnose":
		st := e.Status()
		return ipcResponse{OK: true, Status: &st, Diag: a.diagnose(ctx)}
	case "check_update":
		a.upd.check(ctx, false)
	case "install_update":
		if err := a.upd.requestInstall(); err != nil {
			return errResp(err)
		}
	case "postpone_update":
		if err := a.upd.postpone(); err != nil {
			return errResp(err)
		}
	case "speedtest":
		a.speed.start(false)
	case "send_logs":
		ref, err := sendLogs(ctx, e, a.client, deviceID(), "user", a.gatherLogs)
		if err != nil {
			return errResp(err)
		}
		st := e.Status()
		return ipcResponse{OK: true, Status: &st, LogRef: ref}
	case "certs":
		// The machine's certificates for the Settings picker, plus what the
		// server asks for (from a fresh challenge, when the server answers).
		resp := ipcResponse{OK: true}
		if server, _ := configuredServer(); server != "" {
			cctx, cancel := context.WithTimeout(ctx, 8*time.Second)
			if ch, err := a.client(server).Challenge(cctx); err == nil {
				ch.Nonce = "" // the GUI only needs the requirements
				resp.Challenge = &ch
			}
			cancel()
		}
		var ch clientapi.Challenge
		if resp.Challenge != nil {
			ch = *resp.Challenge
		}
		certs, free, err := openCerts(true)
		defer free()
		if err != nil {
			return errResp(err)
		}
		cl := choices(certs, deviceRule(ch), deviceCertPin())
		resp.Certs = &cl
		return resp
	case "set_device_cert":
		if !validThumb(req.ID) {
			return errResp(errors.New("that isn't a certificate thumbprint"))
		}
		if err := setDeviceCertPin(req.ID); err != nil {
			return errResp(err)
		}
		choice := req.ID
		if choice == "" {
			choice = "automatic"
		}
		a.log.Info("device certificate choice changed", "thumbprint", choice)
	case "dismiss_notice":
		a.notice.dismiss(req.ID)
	default:
		return ipcResponse{Error: "unknown command"}
	}
	st := e.Status()
	ui := a.upd.info()
	si := a.speed.info()
	ip := a.ips.get()
	return ipcResponse{OK: true, Status: &st, Update: &ui, Speed: &si, IPs: &ip, Notice: a.notice.get()}
}

// pipeCall is the GUI side: send one request, read one response.
func pipeCall(req ipcRequest, timeout time.Duration) (ipcResponse, error) {
	dial := 3 * time.Second
	c, err := winio.DialPipe(pipeName, &dial)
	if err != nil {
		return ipcResponse{}, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(timeout))
	if err := json.NewEncoder(c).Encode(req); err != nil {
		return ipcResponse{}, err
	}
	var resp ipcResponse
	err = json.NewDecoder(c).Decode(&resp)
	if req.Cmd == "auth_config" && errors.Is(err, context.DeadlineExceeded) {
		return ipcResponse{Error: "Checking sign-in options timed out. Try again."}, nil
	}
	return resp, err
}

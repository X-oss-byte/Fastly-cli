package authenticate

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/fastly/cli/pkg/cmd"
	"github.com/fastly/cli/pkg/debug"
	fsterr "github.com/fastly/cli/pkg/errors"
	"github.com/fastly/cli/pkg/global"
	"github.com/fastly/cli/pkg/text"
	"github.com/hashicorp/cap/jwt"
	"github.com/hashicorp/cap/oidc"
	"github.com/skratchdot/open-golang/open"
)

// RootCommand is the parent command for all subcommands in this package.
// It should be installed under the primary root command.
type RootCommand struct {
	cmd.Base
}

// AuthRemediation is a generic remediation message for an error authorizing.
const AuthRemediation = "Please re-run the command. If the problem persists, please file an issue: https://github.com/fastly/cli/issues/new?labels=bug&template=bug_report.md"

// Auth0CLIAppURL is the Auth0 device code URL.
const Auth0CLIAppURL = "https://dev-37kjpso9.us.auth0.com"

// Auth0ClientID is the Auth0 Client ID.
const Auth0ClientID = "7TAnqT4DTDhJTyXk9aXcuD48JoHRXK2X"

// Auth0Audience is the unique identifier of the API your app wants to access.
const Auth0Audience = "https://api.secretcdn-stg.net/"

// Auth0RedirectURL is the endpoint Auth0 will pass an authorization code to.
const Auth0RedirectURL = "http://localhost:8080/callback"

// NewRootCommand returns a new command registered in the parent.
func NewRootCommand(parent cmd.Registerer, g *global.Data) *RootCommand {
	var c RootCommand
	c.Globals = g
	c.CmdClause = parent.Command("authenticate", "Authenticate with Fastly (returns temporary, auto-rotated, API token)")
	return &c
}

// Exec implements the command interface.
func (c *RootCommand) Exec(_ io.Reader, out io.Writer) error {
	verifier, err := oidc.NewCodeVerifier()
	if err != nil {
		return fsterr.RemediationError{
			Inner:       fmt.Errorf("failed to generate a code verifier: %w", err),
			Remediation: AuthRemediation,
		}
	}

	result := make(chan authorizationResult)

	s := server{
		result:   result,
		router:   http.NewServeMux(),
		verifier: verifier,
	}
	s.routes()

	var serverErr error

	go func() {
		err := s.startServer()
		if err != nil {
			serverErr = err
		}
	}()

	if serverErr != nil {
		return serverErr
	}

	text.Info(out, "Starting localhost server to handle the authentication flow.")

	authorizationURL, err := generateAuthorizationURL(verifier)
	if err != nil {
		return fsterr.RemediationError{
			Inner:       fmt.Errorf("failed to generate an authorization URL: %w", err),
			Remediation: AuthRemediation,
		}
	}

	text.Break(out)
	text.Description(out, "We're opening the following URL in your default web browser so you may authenticate with Fastly", authorizationURL)

	err = open.Run(authorizationURL)
	if err != nil {
		return fmt.Errorf("failed to open your default browser: %w", err)
	}

	ar := <-result
	if ar.err != nil || ar.jwt.AccessToken == "" {
		return fsterr.RemediationError{
			Inner:       fmt.Errorf("failed to authorize: %w", ar.err),
			Remediation: AuthRemediation,
		}
	}

	// TODO: call Fastly API's /internal/poc/authn/callback endpoint.
	// This is to exchange the access token for an API token.

	// TODO: Persist token to application configuration.
	// How does this work with `fastly profile` (set on the default)?

	return nil
}

type server struct {
	result   chan authorizationResult
	router   *http.ServeMux
	verifier *oidc.S256Verifier
}

func (s *server) startServer() error {
	// TODO: Consider using a random port to avoid local network conflicts.
	// Chat with Auth0 about how to use a random port.
	err := http.ListenAndServe(":8080", s.router)
	if err != nil {
		return fsterr.RemediationError{
			Inner:       fmt.Errorf("failed to start local server: %w", err),
			Remediation: AuthRemediation,
		}
	}
	return nil
}

func (s *server) routes() {
	s.router.HandleFunc("/callback", s.handleCallback())
}

func (s *server) handleCallback() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authorizationCode := r.URL.Query().Get("code")
		if authorizationCode == "" {
			fmt.Fprint(w, "ERROR: no authorization code returned\n")
			s.result <- authorizationResult{
				err: fmt.Errorf("no authorization code returned"),
			}
			return
		}

		// Exchange the authorization code and the code verifier for a JWT.
		codeVerifier := s.verifier.Verifier()
		jwt, err := getJWT(codeVerifier, authorizationCode)
		if err != nil || jwt.AccessToken == "" {
			fmt.Fprint(w, "ERROR: no access token returned\n")
			s.result <- authorizationResult{
				err: fmt.Errorf("no access token returned"),
			}
			return
		}

		fmt.Fprint(w, "Authenticated successfully. Please close this page and return to the Fastly CLI in your terminal.")
		s.result <- authorizationResult{
			jwt: jwt,
		}
	}
}

type authorizationResult struct {
	err error
	jwt JWT
}

func getJWT(codeVerifier, authorizationCode string) (JWT, error) {
	path := "/oauth/token"

	payload := fmt.Sprintf(
		"grant_type=authorization_code&client_id=%s&code_verifier=%s&code=%s&redirect_uri=%s",
		Auth0ClientID,
		codeVerifier,
		authorizationCode,
		"http://localhost:8080", // NOTE: not redirected to, just a security check.
	)

	req, err := http.NewRequest("POST", Auth0CLIAppURL+path, strings.NewReader(payload))
	if err != nil {
		return JWT{}, err
	}

	req.Header.Add("content-type", "application/x-www-form-urlencoded")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return JWT{}, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return JWT{}, fmt.Errorf("failed to exchange code for jwt (status: %s)", res.Status)
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return JWT{}, err
	}

	// NOTE: I use the identifier `j` to avoid overlap with the `jwt` package.
	var j JWT
	err = json.Unmarshal(body, &j)
	if err != nil {
		return JWT{}, err
	}

	err = verifyJWTSignature(j.AccessToken)
	if err != nil {
		return JWT{}, err
	}

	// FIXME: Delete this line.
	_ = debug.PrintStruct(j)

	return j, nil
}

func verifyJWTSignature(accessToken string) error {
	ctx := context.Background()

	keySet, err := jwt.NewJSONWebKeySet(ctx, Auth0CLIAppURL+"/.well-known/jwks.json", "")
	if err != nil {
		return fmt.Errorf("failed to verify signature of access token: %w", err)
	}

	token := accessToken
	claims, err := keySet.VerifySignature(ctx, token)
	if err != nil {
		return fmt.Errorf("failed to verify signature of access token: %w", err)
	}

	// FIXME: Delete this line.
	fmt.Printf("claims:\n%s\n\n", claims)

	return nil
}

// JWT is the API response for an Auth0 Token request.
type JWT struct {
	// AccessToken can be exchanged for a Fastly API token.
	AccessToken string `json:"access_token"`
	// ExpiresIn indicates the lifetime (in seconds) of the access token.
	ExpiresIn int `json:"expires_in"`
	// IDToken contains user information that must be decoded and extracted.
	IDToken string `json:"id_token"`
	// TokenType indicates which HTTP authentication scheme is used (e.g. Bearer).
	TokenType string `json:"token_type"`
}

func generateAuthorizationURL(verifier *oidc.S256Verifier) (string, error) {
	challenge, err := oidc.CreateCodeChallenge(verifier)
	if err != nil {
		return "", err
	}

	authorizationURL := fmt.Sprintf(
		"%s/authorize?audience=%s"+
			"&scope=openid"+
			"&response_type=code&client_id=%s"+
			"&code_challenge=%s"+
			"&code_challenge_method=S256&redirect_uri=%s",
		Auth0CLIAppURL, Auth0Audience, Auth0ClientID, challenge, Auth0RedirectURL)

	return authorizationURL, nil
}

package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/fastly/go-fastly/v8/fastly"
	"github.com/fastly/kingpin"

	"github.com/fastly/cli/pkg/api"
	"github.com/fastly/cli/pkg/api/undocumented"
	"github.com/fastly/cli/pkg/auth"
	"github.com/fastly/cli/pkg/commands/update"
	"github.com/fastly/cli/pkg/commands/version"
	"github.com/fastly/cli/pkg/config"
	"github.com/fastly/cli/pkg/env"
	fsterr "github.com/fastly/cli/pkg/errors"
	"github.com/fastly/cli/pkg/github"
	"github.com/fastly/cli/pkg/global"
	"github.com/fastly/cli/pkg/lookup"
	"github.com/fastly/cli/pkg/manifest"
	"github.com/fastly/cli/pkg/profile"
	"github.com/fastly/cli/pkg/revision"
	"github.com/fastly/cli/pkg/text"
)

// Run constructs the application including all of the subcommands, parses the
// args, invokes the client factory with the token to create a Fastly API
// client, and executes the chosen command, using the provided io.Reader and
// io.Writer for input and output, respectively. In the real CLI, func main is
// just a simple shim to this function; it exists to make end-to-end testing of
// commands easier/possible.
//
// The Run helper should NOT output any error-related information to the out
// io.Writer. All error-related information should be encoded into an error type
// and returned to the caller. This includes usage text.
func Run(opts RunOpts) error {
	// The g will hold generally-applicable configuration parameters
	// from a variety of sources, and is provided to each concrete command.
	g := global.Data{
		Env:        opts.Env,
		ErrLog:     opts.ErrLog,
		Config:     opts.ConfigFile,
		ConfigPath: opts.ConfigPath,
		HTTPClient: opts.HTTPClient,
		Manifest:   *opts.Manifest,
		Output:     opts.Stdout,
	}

	// Set up the main application root, including global flags, and then each
	// of the subcommands. Note that we deliberately don't use some of the more
	// advanced features of the kingpin.Application flags, like env var
	// bindings, because we need to do things like track where a config
	// parameter came from.
	app := kingpin.New("fastly", "A tool to interact with the Fastly API")
	app.Writers(opts.Stdout, io.Discard) // don't let kingpin write error output
	app.UsageContext(&kingpin.UsageContext{
		Template: VerboseUsageTemplate,
		Funcs:    UsageTemplateFuncs,
	})

	// Prevent kingpin from calling os.Exit, this gives us greater control over
	// error states and output control flow.
	app.Terminate(nil)

	// WARNING: kingpin has no way of decorating flags as being "global"
	// therefore if you add/remove a global flag you will also need to update
	// the globalFlags map in pkg/app/usage.go which is used for usage rendering.
	// You should also update `IsGlobalFlagsOnly` in ../cmd/cmd.go
	//
	// NOTE: Global flags (long and short) MUST be unique.
	// A subcommand can't define a flag that is already global.
	// Kingpin will otherwise trigger a runtime panic 🎉
	// Interestingly, short flags can be reused but only across subcommands.
	tokenHelp := fmt.Sprintf("Fastly API token (or via %s)", env.Token)
	app.Flag("accept-defaults", "Accept default options for all interactive prompts apart from Yes/No confirmations").Short('d').BoolVar(&g.Flags.AcceptDefaults)
	app.Flag("auto-yes", "Answer yes automatically to all Yes/No confirmations. This may suppress security warnings").Short('y').BoolVar(&g.Flags.AutoYes)
	app.Flag("endpoint", "Fastly API endpoint").Hidden().StringVar(&g.Flags.Endpoint)
	app.Flag("non-interactive", "Do not prompt for user input - suitable for CI processes. Equivalent to --accept-defaults and --auto-yes").Short('i').BoolVar(&g.Flags.NonInteractive)
	app.Flag("profile", "Switch account profile for single command execution (see also: 'fastly profile switch')").Short('o').StringVar(&g.Flags.Profile)
	app.Flag("quiet", "Silence all output except direct command output. This won't prevent interactive prompts (see: --accept-defaults, --auto-yes, --non-interactive)").Short('q').BoolVar(&g.Flags.Quiet)
	app.Flag("token", tokenHelp).HintAction(env.Vars).Short('t').StringVar(&g.Flags.Token)
	app.Flag("verbose", "Verbose logging").Short('v').BoolVar(&g.Flags.Verbose)

	commands := defineCommands(app, &g, *opts.Manifest, opts)
	command, name, err := processCommandInput(opts, app, &g, commands)
	if err != nil {
		return err
	}
	// We short-circuit the execution for specific cases:
	//
	// - cmd.ArgsIsHelpJSON() == true
	// - shell autocompletion flag provided
	switch name {
	case "help--format=json":
		fallthrough
	case "help--formatjson":
		fallthrough
	case "shell-autocomplete":
		return nil
	}

	if g.Flags.Quiet {
		opts.Manifest.File.SetQuiet(true)
	}

	token, tokenSource := g.Token()

	authWarningMsg := "No API token could be found"

	// NOTE: tokens via FASTLY_API_TOKEN or --token aren't checked for a TTL.
	if tokenSource == lookup.SourceFile && commandRequiresToken(name) {
		var (
			profileData       *config.Profile
			found             bool
			name, profileName string
		)
		switch {
		case g.Flags.Profile != "":
			profileName = g.Flags.Profile
		case g.Manifest.File.Profile != "":
			profileName = g.Manifest.File.Profile
		default:
			profileName = "default"
		}
		for name, profileData = range g.Config.Profiles {
			if (profileName == "default" && profileData.Default) || name == profileName {
				// Once we find the default profile we can update the variable to be the
				// associated profile name so later on we can use that information to
				// update the specific profile.
				if profileName == "default" {
					profileName = name
				}
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("failed to locate '%s' profile", profileName)
		}

		ttl := time.Duration(profileData.AccessTokenTTL) * time.Second
		delta := time.Now().Add(-ttl).Unix()

		// Access Token has expired
		if profileData.AccessTokenCreated < delta {
			ttl := time.Duration(profileData.RefreshTokenTTL) * time.Second
			diff := time.Now().Add(-ttl).Unix()

			if profileData.RefreshTokenCreated < diff {
				authWarningMsg = "Your API token has expired and so has your refresh token"
				// To re-authenticate we simple reset the tokenSource variable.
				// A later conditional block catches it and trigger a re-auth.
				tokenSource = lookup.SourceUndefined
			} else {
				if !g.Flags.Quiet {
					text.Info(opts.Stdout, "Your access token has now expired. We will attempt to refresh it")
				}
				text.Break(opts.Stdout)
				updated, err := auth.RefreshAccessToken(profileData.RefreshToken)
				if err != nil {
					return fmt.Errorf("failed to refresh access token: %w", err)
				}

				claims, err := auth.VerifyJWTSignature(updated.AccessToken)
				if err != nil {
					return fmt.Errorf("failed to verify refreshed JWT: %w", err)
				}

				email, ok := claims["email"]
				if !ok {
					return errors.New("failed to extract email from JWT claims")
				}

				endpoint, _ := g.Endpoint()

				// Exchange the access token for an API token
				resp, err := undocumented.Call(undocumented.CallOptions{
					APIEndpoint: endpoint,
					HTTPClient:  g.HTTPClient,
					HTTPHeaders: []undocumented.HTTPHeader{
						{
							Key:   "Authorization",
							Value: fmt.Sprintf("Bearer %s", updated.AccessToken),
						},
					},
					Method: http.MethodPost,
					Path:   "/login-enhanced",
				})
				if err != nil {
					if apiErr, ok := err.(undocumented.APIError); ok {
						if apiErr.StatusCode != http.StatusConflict {
							err = fmt.Errorf("%w: %d %s", err, apiErr.StatusCode, http.StatusText(apiErr.StatusCode))
						}
					}
					return err
				}

				at := &auth.APIToken{}
				err = json.Unmarshal(resp, at)
				if err != nil {
					return fmt.Errorf("failed to unmarshal json containing API token: %w", err)
				}

				// NOTE: The refresh token can sometimes be refreshed along with the access token.
				// This happens all the time in my testing but according to what is
				// spec'd this apparently is something that _might_ happen.
				// So after we get the refreshed access token, we check to see if the
				// refresh token that was returned by the API call has also changed when
				// compared to the refresh token stored in the CLI config file.
				name, current := profile.Get(profileName, g.Config.Profiles)
				if name == "" {
					return fmt.Errorf("failed to locate '%s' profile", profileName)
				}
				now := time.Now().Unix()
				refreshToken := current.RefreshToken
				refreshTokenCreated := current.RefreshTokenCreated
				refreshTokenTTL := current.RefreshTokenTTL
				if current.RefreshToken != updated.RefreshToken {
					if !g.Flags.Quiet {
						text.Info(opts.Stdout, "Your refresh token was also updated")
					}
					refreshToken = updated.RefreshToken
					refreshTokenCreated = now
					refreshTokenTTL = updated.RefreshExpiresIn
				}

				ps, ok := profile.Edit(profileName, g.Config.Profiles, func(p *config.Profile) {
					p.AccessToken = updated.AccessToken
					p.AccessTokenCreated = now
					p.AccessTokenTTL = updated.ExpiresIn
					p.Email = email.(string)
					p.RefreshToken = refreshToken
					p.RefreshTokenCreated = refreshTokenCreated
					p.RefreshTokenTTL = refreshTokenTTL
					p.Token = at.AccessToken
				})
				if !ok {
					return fsterr.RemediationError{
						Inner:       fmt.Errorf("failed to update '%s' profile with new token data", profileName),
						Remediation: "Run `fastly authenticate` to retry.",
					}
				}
				g.Config.Profiles = ps
				if err := g.Config.Write(g.ConfigPath); err != nil {
					g.ErrLog.Add(err)
					return fmt.Errorf("error saving config file: %w", err)
				}
			}
		}
	}

	// Ensure the user has configured an API token, otherwise trigger the
	// authentication flow (unless calling one of the profile commands).
	if tokenSource == lookup.SourceUndefined && commandRequiresToken(name) {
		for _, command := range commands {
			if command.Name() == "authenticate" {
				text.Warning(opts.Stdout, "%s. We need to open your browser to authenticate you.", authWarningMsg)
				text.Break(opts.Stdout)
				cont, err := text.AskYesNo(opts.Stdout, "Are you sure you want to continue? [y/N]: ", opts.Stdin)
				if err != nil {
					return err
				}
				if !cont {
					return nil
				}
				text.Break(opts.Stdout)

				err = command.Exec(opts.Stdin, opts.Stdout)
				if err != nil {
					return fmt.Errorf("failed to authenticate: %w", err)
				}
				text.Break(opts.Stdout)

				break
			}
		}

		// Recheck for token (should be persisted to profile data).
		token, tokenSource = g.Token()
		if tokenSource == lookup.SourceUndefined {
			return fsterr.ErrNoToken
		}
	}

	if g.Verbose() {
		displayTokenSource(
			tokenSource,
			opts.Stdout,
			env.Token,
			determineProfile(opts.Manifest.File.Profile, g.Flags.Profile, g.Config.Profiles),
		)
	}

	token, err = profile.Init(token, opts.Manifest, &g, opts.Stdin, opts.Stdout)
	if err != nil {
		return err
	}

	// If we are using the token from config file, check the file's permissions
	// to assert if they are not too open or have been altered outside of the
	// application and warn if so.
	segs := strings.Split(name, " ")
	if tokenSource == lookup.SourceFile && (len(segs) > 0 && segs[0] != "profile") {
		if fi, err := os.Stat(config.FilePath); err == nil {
			if mode := fi.Mode().Perm(); mode > config.FilePermissions {
				if !g.Flags.Quiet {
					text.Warning(opts.Stdout, "Unprotected configuration file.")
					fmt.Fprintf(opts.Stdout, "Permissions for '%s' are too open\n", config.FilePath)
					fmt.Fprintf(opts.Stdout, "It is recommended that your configuration file is NOT accessible by others.\n")
					fmt.Fprintln(opts.Stdout)
				}
			}
		}
	}

	endpoint, endpointSource := g.Endpoint()
	if g.Verbose() {
		switch endpointSource {
		case lookup.SourceEnvironment:
			fmt.Fprintf(opts.Stdout, "Fastly API endpoint (via %s): %s\n\n", env.Endpoint, endpoint)
		case lookup.SourceFile:
			fmt.Fprintf(opts.Stdout, "Fastly API endpoint (via config file): %s\n\n", endpoint)
		default:
			fmt.Fprintf(opts.Stdout, "Fastly API endpoint: %s\n\n", endpoint)
		}
	}

	// NOTE: We return error immediately so there's no issue assigning to global.
	// nosemgrep
	g.APIClient, err = opts.APIClient(token, endpoint)
	if err != nil {
		g.ErrLog.Add(err)
		return fmt.Errorf("error constructing Fastly API client: %w", err)
	}

	// NOTE: We return error immediately so there's no issue assigning to global.
	// nosemgrep
	g.RTSClient, err = fastly.NewRealtimeStatsClientForEndpoint(token, fastly.DefaultRealtimeStatsEndpoint)
	if err != nil {
		g.ErrLog.Add(err)
		return fmt.Errorf("error constructing Fastly realtime stats client: %w", err)
	}

	if opts.Versioners.CLI != nil && name != "update" && !version.IsPreRelease(revision.AppVersion) {
		f := update.CheckAsync(
			revision.AppVersion,
			opts.Versioners.CLI,
			g.Flags.Quiet,
		)
		defer f(opts.Stdout) // ...and the printing function second, so we hit the timeout
	}

	return command.Exec(opts.Stdin, opts.Stdout)
}

// RunOpts represent arguments to Run()
type RunOpts struct {
	APIClient  APIClientFactory
	Args       []string
	ConfigFile config.File
	ConfigPath string
	Env        config.Environment
	ErrLog     fsterr.LogInterface
	HTTPClient api.HTTPClient
	Manifest   *manifest.Data
	Stdin      io.Reader
	Stdout     io.Writer
	Versioners Versioners
}

// APIClientFactory creates a Fastly API client (modeled as an api.Interface)
// from a user-provided API token. It exists as a type in order to parameterize
// the Run helper with it: in the real CLI, we can use NewClient from the Fastly
// API client library via RealClient; in tests, we can provide a mock API
// interface via MockClient.
type APIClientFactory func(token, endpoint string) (api.Interface, error)

// Versioners represents all supported versioner types.
type Versioners struct {
	CLI     github.AssetVersioner
	Viceroy github.AssetVersioner
}

// displayTokenSource prints the token source.
func displayTokenSource(source lookup.Source, out io.Writer, token, profileSource string) {
	switch source {
	case lookup.SourceFlag:
		fmt.Fprintf(out, "Fastly API token provided via --token\n")
	case lookup.SourceEnvironment:
		fmt.Fprintf(out, "Fastly API token provided via %s\n", token)
	case lookup.SourceFile:
		fmt.Fprintf(out, "Fastly API token provided via config file (profile: %s)\n", profileSource)
	case lookup.SourceUndefined, lookup.SourceDefault:
		fallthrough
	default:
		fmt.Fprintf(out, "Fastly API token not provided\n")
	}
}

// determineProfile determines if the provided token was acquired via the
// fastly.toml manifest, the --profile flag, or was a default profile from
// within the config.toml application configuration.
func determineProfile(manifestValue, flagValue string, profiles config.Profiles) string {
	if manifestValue != "" {
		return manifestValue + " -- via fastly.toml"
	}
	if flagValue != "" {
		return flagValue
	}
	name, _ := profile.Default(profiles)
	return name
}

// commandRequiresToken determines if the command to be executed is one that
// requires an API token.
func commandRequiresToken(command string) bool {
	command = strings.Split(command, " ")[0]
	switch command {
	case "authenticate", "config", "profile", "update", "version":
		return false
	}
	return true
}

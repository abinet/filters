package main

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/opentracing/opentracing-go"
	log "github.com/sirupsen/logrus"
	"github.com/zalando/skipper/filters"
)

const (
	JwtValidationAnyClaimsName = "JwtValidationAnyClaims"
	jwtValidationCacheKey      = "jwtvalidation"
	JwtValidationConfigPath    = "/.well-known/openid-configuration"
)

type JwtValidationOptions struct {
	Timeout      time.Duration
	Tracer       opentracing.Tracer
	MaxIdleConns int
}

type (
	jwtValidationSpec struct {
		typ     roleCheckType
		options JwtValidationOptions
	}

	//jwtValidationInfo map[string]interface{}

	jwtValidationFilter struct {
		typ        roleCheckType
		authClient *authClient
		claims     []string
		upstreamHeaders map[string]string
	}

	openIDConfig struct {
		Issuer                            string   `json:"issuer"`
		AuthorizationEndpoint             string   `json:"authorization_endpoint"`
		TokenEndpoint                     string   `json:"token_endpoint"`
		UserinfoEndpoint                  string   `json:"userinfo_endpoint"`
		RevocationEndpoint                string   `json:"revocation_endpoint"`
		JwksURI                           string   `json:"jwks_uri"`
		RegistrationEndpoint              string   `json:"registration_endpoint"`
		IntrospectionEndpoint             string   `json:"introspection_endpoint"`
		ResponseTypesSupported            []string `json:"response_types_supported"`
		SubjectTypesSupported             []string `json:"subject_types_supported"`
		IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
		TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
		ClaimsSupported                   []string `json:"claims_supported"`
		ScopesSupported                   []string `json:"scopes_supported"`
		CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	}
)

func getOpenIDConfig(issuerURL string) (*openIDConfig, error) {
	u, err := url.Parse(issuerURL + JwtValidationConfigPath)
	if err != nil {
		return nil, err
	}

	rsp, err := http.Get(u.String())
	if err != nil {
		return nil, err
	}
	defer rsp.Body.Close()

	if rsp.StatusCode != 200 {
		return nil, errInvalidToken
	}
	d := json.NewDecoder(rsp.Body)
	var cfg openIDConfig
	err = d.Decode(&cfg)
	return &cfg, err
}

var issuerAuthClient map[string]*authClient = make(map[string]*authClient)

var rsakeys map[string]*rsa.PublicKey

func NewJwtValidationAnyClaims(timeout time.Duration) filters.Spec {
	return newJwtValidationFilter(checkOAuthTokenintrospectionAnyClaims, timeout)
}

func JwtValidationWithOptions(
	create func(time.Duration) filters.Spec,
	o JwtValidationOptions,
) filters.Spec {
	s := create(o.Timeout)
	ts, ok := s.(*jwtValidationSpec)
	if !ok {
		return s
	}

	ts.options = o
	return ts
}

func newJwtValidationFilter(typ roleCheckType, timeout time.Duration) filters.Spec {
	return &jwtValidationSpec{
		typ: typ,
		options: JwtValidationOptions{
			Timeout: timeout,
			Tracer:  opentracing.NoopTracer{},
		},
	}
}

func InitFilter(opts []string) (filters.Spec, error) {
	return NewJwtValidationAnyClaims(0), nil
}

func (s *jwtValidationSpec) Name() string {
	switch s.typ {
	case checkOAuthTokenintrospectionAnyClaims:
		return JwtValidationAnyClaimsName
	}
	return AuthUnknown
}

func (s *jwtValidationSpec) CreateFilter(args []interface{}) (filters.Filter, error) {
	sargs, err := getStrings(args)
	if err != nil {
		return nil, err
	}
	if len(sargs) < 2 {
		return nil, filters.ErrInvalidFilterParameters
	}

	issuerURL := sargs[0]

	cfg, err := getOpenIDConfig(issuerURL)
	if err != nil {
		return nil, err
	}

	var ac *authClient
	var ok bool
	if ac, ok = issuerAuthClient[issuerURL]; !ok {
		ac, err = newAuthClient(cfg.JwksURI, tokenInfoSpanName, s.options.Timeout, s.options.MaxIdleConns, s.options.Tracer)
		if err != nil {
			return nil, filters.ErrInvalidFilterParameters
		}
		issuerAuthClient[issuerURL] = ac
	}

	f := &jwtValidationFilter{
		typ:        s.typ,
		authClient: ac,
	}

	switch f.typ {
	case checkOAuthTokenintrospectionAnyClaims:
		f.claims = strings.Split(sargs[1], " ")
		if !all(f.claims, cfg.ClaimsSupported) {
			return nil, fmt.Errorf("%v: %s, supported Claims: %v", errUnsupportedClaimSpecified, strings.Join(f.claims, ","), cfg.ClaimsSupported)
		}
	default:
		return nil, filters.ErrInvalidFilterParameters
	}

	// inject additional headers from the access token for upstream applications
	if len(sargs) > 2 && sargs[2] != "" {
		f.upstreamHeaders = make(map[string]string)

		for _, header := range strings.Split(sargs[2], " ") {
			sl := strings.SplitN(header, ":", 2)
			if len(sl) != 2 || sl[0] == "" || sl[1] == "" {
				return nil, fmt.Errorf("%w: malformatted filter for upstream headers %s", filters.ErrInvalidFilterParameters, sl)
			}
			f.upstreamHeaders[sl[0]] = sl[1]
		}
		log.Debugf("Upstream Headers: %v", f.upstreamHeaders)
	}

	return f, nil
}

// String prints nicely the jwtValidationFilter configuration based on the
// configuration and check used.
func (f *jwtValidationFilter) String() string {
	switch f.typ {
	case checkOAuthTokenintrospectionAnyClaims:
		return fmt.Sprintf("%s(%s)", JwtValidationAnyClaimsName, strings.Join(f.claims, ","))
	}
	return AuthUnknown
}

func (f *jwtValidationFilter) validateAnyClaims(token jwt.Token) bool {
	for _, wantedClaim := range f.claims {
		if claims, ok := token.Claims.(jwt.MapClaims); ok {
			if _, ok2 := claims[wantedClaim]; ok2 {
				return true
			}
		}
	}
	return false
}

func (f *jwtValidationFilter) Request(ctx filters.FilterContext) {
	r := ctx.Request()

	var info jwt.Token
	infoTemp, ok := ctx.StateBag()[jwtValidationCacheKey]
	if !ok {
		token, ok := getToken(r)
		if !ok || token == "" {
			unauthorized(ctx, "", missingToken, f.authClient.url.Hostname(), "")
			return
		}

		body, err := f.authClient.getTokeninfo("", ctx)
		if err != nil {
			log.Errorf("Error while getting jwt keys: %v.", err)

			unauthorized(ctx, "", "jwt public keys", f.authClient.url.Hostname(), "")
			return
		}
		//var body map[string]interface{}
		//json.NewDecoder(resp.Body).Decode(&body)
		rsakeys = make(map[string]*rsa.PublicKey)
		if body["keys"] != nil {
			for _, bodykey := range body["keys"].([]interface{}) {
				key := bodykey.(map[string]interface{})
				kid := key["kid"].(string)
				rsakey := new(rsa.PublicKey)
				number, _ := base64.RawURLEncoding.DecodeString(key["n"].(string))
				rsakey.N = new(big.Int).SetBytes(number)
				rsakey.E = 65537
				rsakeys[kid] = rsakey
			}
		} else {
			log.Error("Not able to get public keys")
			unauthorized(ctx, "", "Not able to get public keys", f.authClient.url.Hostname(), "")
			return
		}

		parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
			return rsakeys[token.Header["kid"].(string)], nil
		})
		if err != nil {
			log.Errorf("Error while parsing jwt token : %v.", err)
			unauthorized(ctx, "", "error parsing jwt token", f.authClient.url.Hostname(), "")
			return
		} else if !parsedToken.Valid {
			log.Errorf("Invalid token")
			unauthorized(ctx, "", "Invalid token", f.authClient.url.Hostname(), "")
			return
		} else if parsedToken.Header["alg"] == nil {
			log.Errorf("alg must be defined")
			unauthorized(ctx, "", "alg must be defined", f.authClient.url.Hostname(), "")
			return
		}

		info = *parsedToken
		/*err = json.Unmarshal([]byte(parsedToken.Raw), &info)
		if err != nil {
			log.Errorf("Error while pasing jwt token : %v.", err)
			unauthorized(ctx, "", "error parsing jwt token", f.authClient.url.Hostname(), "")
			return*/
		//}
	} else {
		info = infoTemp.(jwt.Token)
	}

	/*sub, err := info.Sub()
	if err != nil {
		if err != errInvalidTokenintrospectionData {
			log.Errorf("Error while reading token: %v.", err)
		}

		unauthorized(ctx, sub, invalidSub, f.authClient.url.Hostname(), "")
		return
	}

	if !info.Active() {
		unauthorized(ctx, sub, inactiveToken, f.authClient.url.Hostname(), "")
		return
	}*/

	sub := info.Claims.(jwt.MapClaims)["sub"].(string)

	var allowed bool
	switch f.typ {
	case checkOAuthTokenintrospectionAnyClaims, checkSecureOAuthTokenintrospectionAnyClaims:
		allowed = f.validateAnyClaims(info)
	default:
		log.Errorf("Wrong jwtValidationFilter type: %s.", f)
	}
	if !allowed {
		unauthorized(ctx, sub, invalidClaim, f.authClient.url.Hostname(), "")
		return
	}

	authorized(ctx, sub)
	ctx.StateBag()[jwtValidationCacheKey] = info

	// adding upstream headers
	f.setHeaders(ctx, info.Claims.(jwt.MapClaims))
}

func (f *jwtValidationFilter) Response(filters.FilterContext) {}

// Close cleans-up the authClient
func (f *jwtValidationFilter) Close() {
	f.authClient.Close()
}

func (f *jwtValidationFilter) setHeaders(ctx filters.FilterContext, container jwt.MapClaims) (err error) {
	for key, query := range f.upstreamHeaders {
		match := container[query]
		log.Debugf("header: %s results: %s", query, match)
		if match != nil {
			log.Errorf("Lookup failed for upstream header '%s'", query)
			continue
		}
		ctx.Request().Header.Set(key, match.(string))
	}
	return
}

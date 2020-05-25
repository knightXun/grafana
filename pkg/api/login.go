package api

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/grafana/grafana/pkg/api/dtos"
	"github.com/grafana/grafana/pkg/bus"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/infra/metrics"
	"github.com/grafana/grafana/pkg/login"
	"github.com/grafana/grafana/pkg/middleware"
	"github.com/grafana/grafana/pkg/models"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/util"
	"github.com/grafana/grafana/pkg/util/errutil"
)

const (
	ViewIndex            = "index"
	LoginErrorCookieName = "login_error"
)

var setIndexViewData = (*HTTPServer).setIndexViewData
var setIndexTokenViewData = (*HTTPServer).setIndexTokenViewData

var getViewIndex = func() string {
	return ViewIndex
}

func (hs *HTTPServer) ValidateRedirectTo(redirectTo string) error {
	to, err := url.Parse(redirectTo)
	if err != nil {
		return login.ErrInvalidRedirectTo
	}
	if to.IsAbs() {
		return login.ErrAbsoluteRedirectTo
	}
	// when using a subUrl, the redirect_to should start with the subUrl (which contains the leading slash), otherwise the redirect
	// will send the user to the wrong location
	if hs.Cfg.AppSubUrl != "" && !strings.HasPrefix(to.Path, hs.Cfg.AppSubUrl+"/") {
		return login.ErrInvalidRedirectTo
	}
	return nil
}

func (hs *HTTPServer) CookieOptionsFromCfg() middleware.CookieOptions {
	path := "/"
	if len(hs.Cfg.AppSubUrl) > 0 {
		path = hs.Cfg.AppSubUrl
	}
	return middleware.CookieOptions{
		Path:             path,
		Secure:           hs.Cfg.CookieSecure,
		SameSiteDisabled: hs.Cfg.CookieSameSiteDisabled,
		SameSiteMode:     hs.Cfg.CookieSameSiteMode,
	}
}

func (hs *HTTPServer) LoginViewWithCloudToken(c *models.ReqContext) {
	token := c.Params(":token")
	instance := c.Params(":instanceID")

	userID, orgID, err := QueryInstances(instance)
	if err != nil {
		hs.log.Info("Not Found" + err.Error())
		c.Handle(404, "Not Found", nil)
		return
	}

	auth_url := hs.Cfg.CloudAuthUrl

	httpClient := http.Client{
		Timeout: time.Second * 10,
	}

	request, err := http.NewRequest("POST", auth_url, nil)
	if err != nil {
		hs.log.Info("Make Cloud Auth Request Failed: " + err.Error())
		c.Handle(404, "Auth Failed", nil)
		return
	}

	request.Header.Add("Authorization", "Bearer "+token)
	request.Header.Add("Content-Type", "application/json")

	response, err := httpClient.Do(request)

	if err != nil {
		hs.log.Info("Do Cloud Auth Request Failed: " + err.Error())
		c.Handle(404, "Auth Failed", nil)
		return
	}

	if response.StatusCode < 200 || response.StatusCode > 300 {
		hs.log.Info("Do Cloud Auth Request Failed: ErrorCode is ", response.StatusCode)
		c.Handle(404, "Auth Failed", nil)
		return
	}

	data := struct {
		Code    int    `json:"code"`
		Message string `json:"message"`

		Data []struct {
			InstanceID string `json:"instanceID""`
		} `json:"data"`
	}{}

	responseBody, err := ioutil.ReadAll(response.Body)

	if err != nil {
		hs.log.Info("Read Auth Server Response Body Failed", "error", err.Error())
		c.Handle(404, "Auth Failed", nil)
		return
	}

	err = json.Unmarshal(responseBody, &data)
	if err != nil {
		hs.log.Info("Marshal Auth Response Body Failed", "error", err.Error())
		c.Handle(404, "Auth Failed", nil)
		return
	}

	if data.Code != 0 {
		hs.log.Info("Auth Server Response Code !=0 ", "Auth Server Response Message", data.Message)
		c.Handle(404, "Auth Failed", nil)
		return
	}

	found := false
	for _, ins := range data.Data {
		if ins.InstanceID == instance {
			found = true
			break
		}
	}

	if !found {
		hs.log.Info("Auth Server Response Does't contains: ", "instance", instance)
		c.Handle(404, "Auth Failed", nil)
		return
	}

	viewData, err := setIndexTokenViewData(hs, c, userID, orgID)
	if err != nil {
		c.Handle(500, "Failed to get settings", err)
		return
	}

	enabledOAuths := make(map[string]interface{})
	for key, oauth := range setting.OAuthService.OAuthInfos {
		enabledOAuths[key] = map[string]string{"name": oauth.Name}
	}

	viewData.Settings["oauth"] = enabledOAuths
	viewData.Settings["samlEnabled"] = hs.License.HasValidLicense() && hs.Cfg.SAMLEnabled

	if loginError, ok := tryGetEncryptedCookie(c, LoginErrorCookieName); ok {
		middleware.DeleteCookie(c.Resp, LoginErrorCookieName, hs.CookieOptionsFromCfg)
		viewData.Settings["loginError"] = loginError
		c.HTML(200, getViewIndex(), viewData)
		return
	}

	hs.log.Info("Auth Users Done")

	user := &models.User{Id: userID, Email: c.SignedInUser.Email, Login: instance}
	err = hs.loginUserWithUser(user, c)
	if err != nil {
		hs.log.Info("Auth User Login Failed: ", err.Error())
		c.Handle(500, "Failed to sign in user", err)
		return
	}

	hs.log.Info("Handle Login Requests Done")
	c.Redirect(setting.AppSubUrl + "/")
}

func (hs *HTTPServer) LoginViewWithToken(c *models.ReqContext) {
	userName := c.Params(":userName")
	token := c.Params(":token")

	instance := c.Params(":instanceID")

	userID, orgID, err := QueryInstances(instance)
	if err != nil {
		hs.log.Info("Not Found" + err.Error())
		c.Handle(404, "Not Found", nil)
		return
	}

	auth_url := hs.Cfg.CloudAuthUrl

	httpClient := http.Client{
		Timeout: time.Second * 10,
	}

	request, err := http.NewRequest("POST", auth_url, nil)
	if err != nil {
		hs.log.Info("Make Cloud Auth Request Failed: " + err.Error())
		c.Handle(404, "Auth Failed", nil)
		return
	}

	userAndPasswd := userName + ":" + token
	request.Header.Add("Authorization", "Nebula "+base64.StdEncoding.EncodeToString([]byte(userAndPasswd)))
	request.Header.Add("Content-Type", "application/json")

	response, err := httpClient.Do(request)

	if err != nil {
		hs.log.Info("Do Cloud Auth Request Failed: " + err.Error())
		c.Handle(404, "Auth Failed", nil)
		return
	}

	if response.StatusCode < 200 || response.StatusCode > 300 {
		hs.log.Info("Do Cloud Auth Request Failed: ErrorCode is ", response.StatusCode)
		c.Handle(404, "Auth Failed", nil)
		return
	}

	viewData, err := setIndexTokenViewData(hs, c, userID, orgID)
	if err != nil {
		c.Handle(500, "Failed to get settings", err)
		return
	}

	enabledOAuths := make(map[string]interface{})
	for key, oauth := range setting.OAuthService.OAuthInfos {
		enabledOAuths[key] = map[string]string{"name": oauth.Name}
	}

	viewData.Settings["oauth"] = enabledOAuths
	viewData.Settings["samlEnabled"] = hs.License.HasValidLicense() && hs.Cfg.SAMLEnabled

	if loginError, ok := tryGetEncryptedCookie(c, LoginErrorCookieName); ok {
		middleware.DeleteCookie(c.Resp, LoginErrorCookieName, hs.CookieOptionsFromCfg)
		viewData.Settings["loginError"] = loginError
		c.HTML(200, getViewIndex(), viewData)
		return
	}

	hs.log.Info("Auth Users Done")

	user := &models.User{Id: userID, Email: c.SignedInUser.Email, Login: instance}
	err = hs.loginUserWithUser(user, c)
	if err != nil {
		hs.log.Info("Auth User Login Failed: ", err.Error())
		c.Handle(500, "Failed to sign in user", err)
		return
	}

	hs.log.Info("Handle Login Requests Done")
	c.Redirect(setting.AppSubUrl + "/")
}

func (hs *HTTPServer) LoginView(c *models.ReqContext) {
	viewData, err := setIndexViewData(hs, c)
	if err != nil {
		c.Handle(500, "Failed to get settings", err)
		return
	}

	enabledOAuths := make(map[string]interface{})
	for key, oauth := range setting.OAuthService.OAuthInfos {
		enabledOAuths[key] = map[string]string{"name": oauth.Name}
	}

	viewData.Settings["oauth"] = enabledOAuths
	viewData.Settings["samlEnabled"] = hs.License.HasValidLicense() && hs.Cfg.SAMLEnabled

	if loginError, ok := tryGetEncryptedCookie(c, LoginErrorCookieName); ok {
		//this cookie is only set whenever an OAuth login fails
		//therefore the loginError should be passed to the view data
		//and the view should return immediately before attempting
		//to login again via OAuth and enter to a redirect loop
		middleware.DeleteCookie(c.Resp, LoginErrorCookieName, hs.CookieOptionsFromCfg)
		viewData.Settings["loginError"] = loginError
		c.HTML(200, getViewIndex(), viewData)
		return
	}

	if tryOAuthAutoLogin(c) {
		return
	}

	if c.IsSignedIn {
		// Assign login token to auth proxy users if enable_login_token = true
		if setting.AuthProxyEnabled && setting.AuthProxyEnableLoginToken {
			user := &models.User{Id: c.SignedInUser.UserId, Email: c.SignedInUser.Email, Login: c.SignedInUser.Login}
			err := hs.loginUserWithUser(user, c)
			if err != nil {
				c.Handle(500, "Failed to sign in user", err)
				return
			}
		}

		if redirectTo, _ := url.QueryUnescape(c.GetCookie("redirect_to")); len(redirectTo) > 0 {
			if err := hs.ValidateRedirectTo(redirectTo); err != nil {
				// the user is already logged so instead of rendering the login page with error
				// it should be redirected to the home page.
				log.Debug("Ignored invalid redirect_to cookie value: %v", redirectTo)
				redirectTo = hs.Cfg.AppSubUrl + "/"
			}
			middleware.DeleteCookie(c.Resp, "redirect_to", hs.CookieOptionsFromCfg)
			c.Redirect(redirectTo)
			return
		}

		c.Redirect(setting.AppSubUrl + "/")
		return
	}

	c.HTML(200, getViewIndex(), viewData)
}

func tryOAuthAutoLogin(c *models.ReqContext) bool {
	if !setting.OAuthAutoLogin {
		return false
	}
	oauthInfos := setting.OAuthService.OAuthInfos
	if len(oauthInfos) != 1 {
		log.Warn("Skipping OAuth auto login because multiple OAuth providers are configured")
		return false
	}
	for key := range setting.OAuthService.OAuthInfos {
		redirectUrl := setting.AppSubUrl + "/login/" + key
		log.Info("OAuth auto login enabled. Redirecting to " + redirectUrl)
		c.Redirect(redirectUrl, 307)
		return true
	}
	return false
}

func (hs *HTTPServer) LoginAPIPing(c *models.ReqContext) Response {
	if c.IsSignedIn || c.IsAnonymous {
		return JSON(200, "Logged in")
	}

	return Error(401, "Unauthorized", nil)
}

func (hs *HTTPServer) LoginPost(c *models.ReqContext, cmd dtos.LoginCommand) Response {
	if setting.DisableLoginForm {
		return Error(401, "Login is disabled", nil)
	}

	authQuery := &models.LoginUserQuery{
		ReqContext: c,
		Username:   cmd.User,
		Password:   cmd.Password,
		IpAddress:  c.Req.RemoteAddr,
	}

	if err := bus.Dispatch(authQuery); err != nil {
		e401 := Error(401, "Invalid username or password", err)
		if err == login.ErrInvalidCredentials || err == login.ErrTooManyLoginAttempts {
			return e401
		}

		// Do not expose disabled status,
		// just show incorrect user credentials error (see #17947)
		if err == login.ErrUserDisabled {
			hs.log.Warn("User is disabled", "user", cmd.User)
			return e401
		}

		return Error(500, "Error while trying to authenticate user", err)
	}

	user := authQuery.User

	err := hs.loginUserWithUser(user, c)
	if err != nil {
		return Error(500, "Error while signing in user", err)
	}

	result := map[string]interface{}{
		"message": "Logged in",
	}

	if redirectTo, _ := url.QueryUnescape(c.GetCookie("redirect_to")); len(redirectTo) > 0 {
		if err := hs.ValidateRedirectTo(redirectTo); err == nil {
			result["redirectUrl"] = redirectTo
		} else {
			log.Info("Ignored invalid redirect_to cookie value: %v", redirectTo)
		}
		middleware.DeleteCookie(c.Resp, "redirect_to", hs.CookieOptionsFromCfg)
	}

	metrics.MApiLoginPost.Inc()
	return JSON(200, result)
}

func (hs *HTTPServer) loginUserWithUser(user *models.User, c *models.ReqContext) error {
	if user == nil {
		return errors.New("could not login user")
	}

	userToken, err := hs.AuthTokenService.CreateToken(c.Req.Context(), user.Id, c.RemoteAddr(), c.Req.UserAgent())
	if err != nil {
		return errutil.Wrap("failed to create auth token", err)
	}

	hs.log.Info("Successful Login", "User", user.Email)
	middleware.WriteSessionCookie(c, userToken.UnhashedToken, hs.Cfg.LoginMaxLifetimeDays)
	return nil
}

func (hs *HTTPServer) Logout(c *models.ReqContext) {
	if err := hs.AuthTokenService.RevokeToken(c.Req.Context(), c.UserToken); err != nil && err != models.ErrUserTokenNotFound {
		hs.log.Error("failed to revoke auth token", "error", err)
	}

	middleware.WriteSessionCookie(c, "", -1)

	if setting.SignoutRedirectUrl != "" {
		c.Redirect(setting.SignoutRedirectUrl)
	} else {
		hs.log.Info("Successful Logout", "User", c.Email)
		c.Redirect(setting.AppSubUrl + "/login")
	}
}

func tryGetEncryptedCookie(ctx *models.ReqContext, cookieName string) (string, bool) {
	cookie := ctx.GetCookie(cookieName)
	if cookie == "" {
		return "", false
	}

	decoded, err := hex.DecodeString(cookie)
	if err != nil {
		return "", false
	}

	decryptedError, err := util.Decrypt(decoded, setting.SecretKey)
	return string(decryptedError), err == nil
}

func (hs *HTTPServer) trySetEncryptedCookie(ctx *models.ReqContext, cookieName string, value string, maxAge int) error {
	encryptedError, err := util.Encrypt([]byte(value), setting.SecretKey)
	if err != nil {
		return err
	}

	middleware.WriteCookie(ctx.Resp, cookieName, hex.EncodeToString(encryptedError), 60, hs.CookieOptionsFromCfg)

	return nil
}

func (hs *HTTPServer) redirectWithError(ctx *models.ReqContext, err error, v ...interface{}) {
	ctx.Logger.Error(err.Error(), v...)
	if err := hs.trySetEncryptedCookie(ctx, LoginErrorCookieName, err.Error(), 60); err != nil {
		hs.log.Error("Failed to set encrypted cookie", "err", err)
	}

	ctx.Redirect(setting.AppSubUrl + "/login")
}

func (hs *HTTPServer) RedirectResponseWithError(ctx *models.ReqContext, err error, v ...interface{}) *RedirectResponse {
	ctx.Logger.Error(err.Error(), v...)
	if err := hs.trySetEncryptedCookie(ctx, LoginErrorCookieName, err.Error(), 60); err != nil {
		hs.log.Error("Failed to set encrypted cookie", "err", err)
	}

	return Redirect(setting.AppSubUrl + "/login")
}

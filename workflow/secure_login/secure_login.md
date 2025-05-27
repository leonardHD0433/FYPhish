leonardHD0433: @workspace i want to completely rework the login process into my gophish website where i want a secure login method by implementing google sign in and 2fa using the authenticator app, the website will have an exisiting admin account tied to the website as there will be no option for the user to create a new account, only the admin can add the accounts from the dashboard. Help me identify the files in the workspace that should be considered for this rework and map out an outline on how should i start with the implementation. think step by step

Workspace: Collecting workspace information# Implementing Google Sign-In and 2FA in Gophish

Based on my analysis of your workspace, here's how you can implement Google Sign-In and 2FA authentication in your Gophish fork.

## Key Files to Modify

### Backend (Auth & Controllers)
1. auth.go - Core authentication functionality
2. user.go - User model that needs new fields for Google ID and 2FA
3. route.go - Handles login/logout routes
4. middleware.go - Contains RequireLogin middleware
5. session.go - Session management

### Frontend (Templates & JS)
1. login.html - Login page that needs Google button
2. settings.html - Where users will set up 2FA
3. gophish.js - Core JS functions
4. users.js - User management functions

### Database
1. models.go - Contains database setup code

## Implementation Plan

### 1. Database Schema Updates

First, modify the User model in user.go to add fields for Google authentication and 2FA:

```go
// User represents the user model for gophish.
type User struct {
    Id                     int64     `json:"id"`
    Username               string    `json:"username" sql:"not null;unique"`
    Hash                   string    `json:"-"`
    ApiKey                 string    `json:"api_key" sql:"not null;unique"`
    Role                   Role      `json:"role" gorm:"association_autoupdate:false;association_autocreate:false"`
    RoleID                 int64     `json:"-"`
    PasswordChangeRequired bool      `json:"password_change_required"`
    AccountLocked          bool      `json:"account_locked"`
    LastLogin              time.Time `json:"last_login"`
    
    // New fields for authentication
    GoogleID               string    `json:"-" sql:"unique"`
    TwoFactorSecret        string    `json:"-"`
    TwoFactorEnabled       bool      `json:"two_factor_enabled"`
}
```

### 2. Google OAuth Integration

Add Google OAuth2 dependencies and configuration:

```sh
go get golang.org/x/oauth2
go get google.golang.org/api/oauth2/v2
```

Create a new file for Google OAuth configuration:

````go
package auth

import (
    "context"
    "crypto/rand"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "io/ioutil"
    "net/http"
    
    "golang.org/x/oauth2"
    "golang.org/x/oauth2/google"
    googleOauth "google.golang.org/api/oauth2/v2"
    "github.com/gophish/gophish/config"
    "github.com/gophish/gophish/models"
)

var (
    // GoogleOAuthConfig is the OAuth2 config for Google
    GoogleOAuthConfig *oauth2.Config
)

// InitGoogleOAuth initializes the Google OAuth configuration
func InitGoogleOAuth(conf *config.Config) {
    GoogleOAuthConfig = &oauth2.Config{
        ClientID:     conf.GoogleClientID,
        ClientSecret: conf.GoogleClientSecret,
        RedirectURL:  conf.PhishURL + "/oauth/callback",
        Scopes: []string{
            "https://www.googleapis.com/auth/userinfo.email",
            "https://www.googleapis.com/auth/userinfo.profile",
        },
        Endpoint: google.Endpoint,
    }
}

// GenerateStateOAuthCookie generates a random state for OAuth
func GenerateStateOAuthCookie(w http.ResponseWriter) string {
    b := make([]byte, 16)
    rand.Read(b)
    state := base64.URLEncoding.EncodeToString(b)
    expiration := time.Now().Add(365 * 24 * time.Hour)
    cookie := http.Cookie{
        Name:     "oauthstate",
        Value:    state,
        Expires:  expiration,
        HttpOnly: true,
    }
    http.SetCookie(w, &cookie)
    return state
}

// GetUserInfoFromGoogle gets user info from Google API
func GetUserInfoFromGoogle(code string) (*googleOauth.Userinfo, error) {
    token, err := GoogleOAuthConfig.Exchange(context.Background(), code)
    if err != nil {
        return nil, fmt.Errorf("code exchange failed: %s", err.Error())
    }
    
    client := GoogleOAuthConfig.Client(context.Background(), token)
    service, err := googleOauth.New(client)
    if err != nil {
        return nil, err
    }
    
    userInfo, err := service.Userinfo.Get().Do()
    if err != nil {
        return nil, err
    }
    
    return userInfo, nil
}

// GetOrCreateUserByGoogleID gets or creates a user by Google ID
func GetOrCreateUserByGoogleID(googleID string, email string) (models.User, error) {
    user, err := models.GetUserByGoogleID(googleID)
    if err == nil {
        return user, nil
    }
    
    // Try to find the user by email
    user, err = models.GetUserByUsername(email)
    if err == nil {
        // Update the Google ID for this user
        user.GoogleID = googleID
        err = models.PutUser(&user)
        return user, err
    }
    
    // User doesn't exist, but we don't create accounts automatically
    return models.User{}, fmt.Errorf("user not found and auto-creation disabled")
}
````

### 3. Add 2FA Support

Add 2FA support using TOTP (Time-based One-Time Password):

```sh
go get github.com/pquerna/otp
```

Create a new file for 2FA:

````go
package auth

import (
    "bytes"
    "encoding/base64"
    "fmt"
    "image/png"
    "time"
    
    "github.com/pquerna/otp"
    "github.com/pquerna/otp/totp"
)

// GenerateTOTPSecret generates a new TOTP secret
func GenerateTOTPSecret(username string) (string, string, error) {
    key, err := totp.Generate(totp.GenerateOpts{
        Issuer:      "Gophish",
        AccountName: username,
    })
    if err != nil {
        return "", "", err
    }
    
    // Generate QR code
    var buf bytes.Buffer
    img, err := key.Image(200, 200)
    if err != nil {
        return "", "", err
    }
    
    png.Encode(&buf, img)
    
    qrcode := base64.StdEncoding.EncodeToString(buf.Bytes())
    return key.Secret(), qrcode, nil
}

// ValidateTOTP validates a TOTP code
func ValidateTOTP(secret, code string) bool {
    return totp.Validate(code, secret)
}
````

### 4. Update the Controller for Google Auth and 2FA

Modify route.go to add new handlers:

````go
// Add these new handler methods to the AdminServer struct

// GoogleLogin initiates Google OAuth flow
func (as *AdminServer) GoogleLogin(w http.ResponseWriter, r *http.Request) {
    oauthState := auth.GenerateStateOAuthCookie(w)
    url := auth.GoogleOAuthConfig.AuthCodeURL(oauthState)
    http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

// GoogleCallback handles the OAuth callback
func (as *AdminServer) GoogleCallback(w http.ResponseWriter, r *http.Request) {
    oauthState, _ := r.Cookie("oauthstate")
    
    if r.FormValue("state") != oauthState.Value {
        http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
        return
    }
    
    userInfo, err := auth.GetUserInfoFromGoogle(r.FormValue("code"))
    if err != nil {
        log.Error(err)
        Flash(w, r, "danger", "Error authenticating with Google")
        http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
        return
    }
    
    user, err := auth.GetOrCreateUserByGoogleID(userInfo.Id, userInfo.Email)
    if err != nil {
        log.Error(err)
        Flash(w, r, "danger", "No matching user account found")
        http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
        return
    }
    
    // If 2FA is enabled, redirect to 2FA verification
    if user.TwoFactorEnabled {
        session := ctx.Get(r, "session").(*sessions.Session)
        session.Values["temp_user_id"] = user.Id
        session.Save(r, w)
        http.Redirect(w, r, "/verify-2fa", http.StatusTemporaryRedirect)
        return
    }
    
    // Otherwise, log in directly
    session := ctx.Get(r, "session").(*sessions.Session)
    session.Values["id"] = user.Id
    session.Save(r, w)
    
    user.LastLogin = time.Now().UTC()
    err = models.PutUser(&user)
    if err != nil {
        log.Error(err)
    }
    
    http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}

// Verify2FA shows the 2FA verification form
func (as *AdminServer) Verify2FA(w http.ResponseWriter, r *http.Request) {
    session := ctx.Get(r, "session").(*sessions.Session)
    tempUserID, ok := session.Values["temp_user_id"].(int64)
    if !ok {
        http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
        return
    }
    
    params := newTemplateParams(r)
    params.Title = "Two-Factor Authentication"
    params.Flashes = session.Flashes()
    session.Save(r, w)
    
    getTemplate(w, "2fa").ExecuteTemplate(w, "base", params)
}

// Validate2FA validates a 2FA code
func (as *AdminServer) Validate2FA(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }
    
    session := ctx.Get(r, "session").(*sessions.Session)
    tempUserID, ok := session.Values["temp_user_id"].(int64)
    if !ok {
        http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
        return
    }
    
    code := r.FormValue("code")
    user, err := models.GetUser(tempUserID)
    if err != nil {
        log.Error(err)
        Flash(w, r, "danger", "Invalid user")
        http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
        return
    }
    
    if !auth.ValidateTOTP(user.TwoFactorSecret, code) {
        Flash(w, r, "danger", "Invalid authentication code")
        http.Redirect(w, r, "/verify-2fa", http.StatusTemporaryRedirect)
        return
    }
    
    // 2FA passed, log in the user
    delete(session.Values, "temp_user_id")
    session.Values["id"] = user.Id
    session.Save(r, w)
    
    user.LastLogin = time.Now().UTC()
    err = models.PutUser(&user)
    if err != nil {
        log.Error(err)
    }
    
    http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}

// Setup2FA shows the 2FA setup page
func (as *AdminServer) Setup2FA(w http.ResponseWriter, r *http.Request) {
    u := ctx.Get(r, "user").(models.User)
    
    // Generate a new TOTP secret
    secret, qrcode, err := auth.GenerateTOTPSecret(u.Username)
    if err != nil {
        log.Error(err)
        http.Error(w, "Error generating 2FA secret", http.StatusInternalServerError)
        return
    }
    
    session := ctx.Get(r, "session").(*sessions.Session)
    session.Values["temp_2fa_secret"] = secret
    session.Save(r, w)
    
    params := newTemplateParams(r)
    params.Title = "Set Up Two-Factor Authentication"
    params.Data = map[string]interface{}{
        "QRCode": qrcode,
        "Secret": secret,
    }
    
    getTemplate(w, "setup_2fa").ExecuteTemplate(w, "base", params)
}

// Confirm2FA confirms and enables 2FA for a user
func (as *AdminServer) Confirm2FA(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }
    
    u := ctx.Get(r, "user").(models.User)
    session := ctx.Get(r, "session").(*sessions.Session)
    
    secret, ok := session.Values["temp_2fa_secret"].(string)
    if !ok {
        Flash(w, r, "danger", "Invalid setup session")
        http.Redirect(w, r, "/settings", http.StatusTemporaryRedirect)
        return
    }
    
    code := r.FormValue("code")
    if !auth.ValidateTOTP(secret, code) {
        Flash(w, r, "danger", "Invalid authentication code")
        http.Redirect(w, r, "/setup-2fa", http.StatusTemporaryRedirect)
        return
    }
    
    // Code is valid, enable 2FA
    u.TwoFactorSecret = secret
    u.TwoFactorEnabled = true
    err := models.PutUser(&u)
    if err != nil {
        log.Error(err)
        Flash(w, r, "danger", "Error saving 2FA settings")
        http.Redirect(w, r, "/settings", http.StatusTemporaryRedirect)
        return
    }
    
    delete(session.Values, "temp_2fa_secret")
    session.Save(r, w)
    
    Flash(w, r, "success", "Two-factor authentication enabled successfully!")
    http.Redirect(w, r, "/settings", http.StatusTemporaryRedirect)
}

// Disable2FA disables 2FA for a user
func (as *AdminServer) Disable2FA(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }
    
    u := ctx.Get(r, "user").(models.User)
    
    // Disable 2FA
    u.TwoFactorEnabled = false
    u.TwoFactorSecret = ""
    err := models.PutUser(&u)
    if err != nil {
        log.Error(err)
        Flash(w, r, "danger", "Error saving 2FA settings")
        http.Redirect(w, r, "/settings", http.StatusTemporaryRedirect)
        return
    }
    
    Flash(w, r, "success", "Two-factor authentication disabled successfully!")
    http.Redirect(w, r, "/settings", http.StatusTemporaryRedirect)
}
````

### 5. Update the Routes

Modify the route setup in route.go to add new routes:

```go
// Add these routes to the RegisterRoutes function
router.HandleFunc("/oauth/google", as.GoogleLogin)
router.HandleFunc("/oauth/callback", as.GoogleCallback)
router.HandleFunc("/verify-2fa", as.Verify2FA)
router.HandleFunc("/validate-2fa", as.Validate2FA)
router.HandleFunc("/setup-2fa", Use(as.Setup2FA, RequireLogin))
router.HandleFunc("/confirm-2fa", Use(as.Confirm2FA, RequireLogin))
router.HandleFunc("/disable-2fa", Use(as.Disable2FA, RequireLogin))
```

### 6. Create New Templates

Create a 2FA verification template:

````html
{{ define "body" }}
<div class="container">
    <form class="form-signin" action="/validate-2fa" method="POST">
        <img id="logo" src="/images/logo_purple.png" />
        <h2 class="form-signin-heading">Two-Factor Authentication</h2>
        {{template "flashes" .Flashes}}
        <p>Enter the verification code from your authenticator app:</p>
        <input type="text" name="code" class="form-control" placeholder="Authentication code" required autofocus>
        <input type="hidden" name="csrf_token" value="{{.Token}}" />
        <br />
        <button class="btn btn-lg btn-primary btn-block" type="submit">Verify</button>
    </form>
</div>
{{ end }}
````

Create a 2FA setup template:

````html
{{ define "body" }}
<div class="container">
    <div class="col-md-6 col-md-offset-3">
        <h2>Set Up Two-Factor Authentication</h2>
        <p>Scan this QR code with your authenticator app (like Google Authenticator, Authy, or Microsoft Authenticator):</p>
        
        <div class="text-center">
            <img src="data:image/png;base64,{{.Data.QRCode}}" alt="QR Code" />
        </div>
        
        <p>Or manually enter this code: <code>{{.Data.Secret}}</code></p>
        
        <form action="/confirm-2fa" method="POST">
            <div class="form-group">
                <label for="code">Verification Code:</label>
                <input type="text" class="form-control" id="code" name="code" placeholder="Enter the code from your app" required>
            </div>
            <input type="hidden" name="csrf_token" value="{{.Token}}" />
            <button type="submit" class="btn btn-primary">Verify and Enable 2FA</button>
        </form>
    </div>
</div>
{{ end }}
````

### 7. Update the Login Page

Modify login.html to add Google Sign-In:

````html
// Add inside the login form
<div class="form-signin">
    <!-- Existing login form -->
    
    <hr>
    <p class="text-center">Or sign in with:</p>
    
    <a href="/oauth/google" class="btn btn-lg btn-danger btn-block">
        <i class="fa fa-google"></i> Sign in with Google
    </a>
</div>
````

### 8. Update the Settings Page

Modify settings.html to add 2FA settings:

````html
// Add to the settings tab
<div class="row">
    <label class="col-sm-2 control-label form-label">Two-Factor Authentication:</label>
    <div class="col-md-6">
        {{if .User.TwoFactorEnabled}}
            <p><span class="label label-success">Enabled</span></p>
            <form action="/disable-2fa" method="POST">
                <input type="hidden" name="csrf_token" value="{{.Token}}" />
                <button class="btn btn-danger" type="submit">Disable 2FA</button>
            </form>
        {{else}}
            <p><span class="label label-default">Disabled</span></p>
            <a href="/setup-2fa" class="btn btn-primary">Set Up 2FA</a>
        {{end}}
    </div>
</div>
````

### 9. Update Config to Include Google OAuth

Update config.go to include Google OAuth settings:

````go
// Update the Config struct

// Config represents the configuration information.
type Config struct {
    AdminConf      AdminServer      `json:"admin_server"`
    PhishConf      PhishServer      `json:"phish_server"`
    DBName         string           `json:"db_name"`
    DBPath         string           `json:"db_path"`
    DBSSLCaPath    string           `json:"db_ssl_ca_path"`
    DBSSLKeyPath   string           `json:"db_ssl_key_path"`
    DBSSLCertPath  string           `json:"db_ssl_cert_path"`
    MigrationsPath string           `json:"migrations_prefix"`
    ContactAddress string           `json:"contact_address"`
    Logging        map[string]string `json:"logging"`
    
    // New fields for Google OAuth
    GoogleClientID     string `json:"google_client_id"`
    GoogleClientSecret string `json:"google_client_secret"`
}
````

### 10. Initialize Google OAuth in Main Function

Update gophish.go to initialize Google OAuth:

```go
// Add to main() function after loading config
// Initialize Google OAuth
auth.InitGoogleOAuth(conf)
```

## Testing Your Implementation

1. Update the config.json file to include your Google OAuth credentials:
```json
{
  "google_client_id": "YOUR_CLIENT_ID",
  "google_client_secret": "YOUR_CLIENT_SECRET",
  "admin_server": {
    ...
  }
}
```

2. Build and run the application:
```sh
go build
./gophish
```

3. Test the Google login flow and 2FA setup

## Security Considerations

1. Ensure all sensitive data (2FA secrets, Google tokens) are stored securely
2. Add rate limiting to prevent brute force attacks on 2FA
3. Consider adding backup codes for 2FA recovery
4. Audit and log all authentication events

This implementation maintains the existing admin account while enhancing security with Google Sign-In and 2FA using authenticator apps.

Similar code found with 1 license type
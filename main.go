package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"

	phtml "golang.org/x/net/html"

	log "github.com/sirupsen/logrus"

	"github.com/gorilla/securecookie"
	"github.com/spf13/viper"
	"github.com/vartanbeno/go-reddit/v2/reddit"
	"golang.org/x/oauth2"
)

var (
	useragent         string
	subreddit         string
	redditOauthConfig *oauth2.Config
	DurationTemporary oauth2.AuthCodeOption = oauth2.SetAuthURLParam("duration", "temporary")
	rclient           *reddit.Client
	sc                *securecookie.SecureCookie
)

// OAuth response
type tokenJSON struct {
	AccessToken  string `json:"access_token,omitempty"`
	TokenType    string `json:"token_type,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresIn    int32  `json:"expires_in,omitempty"`
}

// Reddit response to /v1/me
// Removed many unused fields
type UserResp struct {
	ID   string `json:"id"`
	Name string `json:"name,"`
}

// Reddit response to /about/moderators
// Removed unused fields
type ModsResp struct {
	Kind string `json:"kind"`
	Data struct {
		Children []struct {
			Name           string   `json:"name"`
			ModPermissions []string `json:"mod_permissions"`
		} `json:"children"`
	} `json:"data"`
}

func init() {
	// load config
	viper.SetConfigFile(".env")
	viper.ReadInConfig()
	subreddit = viper.GetString("subreddit")
	useragent = viper.GetString("useragent")
	// securecookie with random numbers, so cookie will be invalid after restart
	sc = securecookie.New(securecookie.GenerateRandomKey(32), securecookie.GenerateRandomKey(32))
	redditOauthConfig = &oauth2.Config{
		RedirectURL:  viper.GetString("O_HOST") + "/callback",
		ClientID:     viper.GetString("O_CLIENT_ID"),
		ClientSecret: viper.GetString("O_CLIENT_SECRET"),
		Scopes:       []string{"read", "identity"},
		Endpoint: oauth2.Endpoint{
			AuthURL:   "https://www.reddit.com/api/v1/authorize",
			TokenURL:  "https://www.reddit.com/api/v1/access_token",
			AuthStyle: oauth2.AuthStyleInHeader,
		},
	}
	log.SetFormatter(&log.TextFormatter{})
	log.SetOutput(os.Stdout)
	log.SetLevel(log.Level(viper.GetUint32("logLevel")))
}

// Perform connection to reddit and then start HTTP Server
func main() {
	var err error
	rclient, err = reddit.NewClient(
		reddit.Credentials{
			ID:       viper.GetString("R_CLIENT_ID"),
			Secret:   viper.GetString("R_CLIENT_SECRET"),
			Username: viper.GetString("R_USERNAME"),
			Password: viper.GetString("R_PASSWORD"),
		},
		reddit.WithUserAgent(useragent))
	if err != nil {
		log.WithError(err).Panic("Reddit client error")
		return
	}
	// as a test, fetch top post from subreddit
	posts, _, err := rclient.Subreddit.TopPosts(context.Background(), subreddit, &reddit.ListPostOptions{
		ListOptions: reddit.ListOptions{
			Limit: 1,
		},
		Time: "all",
	})
	if err != nil {
		log.WithError(err).Panic("Reddit test error")
		return
	}
	if len(posts) != 1 {
		log.Panic("Reddit read test error")
		return
	}
	log.Info("Login ok")

	// HTTP Server
	mux := http.NewServeMux()
	mux.HandleFunc("/", getRoot)
	mux.HandleFunc("/login", handleLogin)
	mux.HandleFunc("/callback", handleCallback)
	mux.HandleFunc("/post", handlePost)
	mux.HandleFunc("/submit", handleSubmit)
	mux.HandleFunc("/title", handleGetTitle)

	log.Info("Serving on :3000")
	err = http.ListenAndServe("127.0.0.1:3000", mux)
	if err != nil {
		fmt.Printf("error listening: %s\n", err)
	}
}

// Set secure cookies in user session
func SetCookieHandler(w http.ResponseWriter, r *http.Request, user string, token string) {
	value := map[string]string{
		"user":  user,
		"token": token,
	}
	if encoded, err := sc.Encode("cookie-name", value); err == nil {
		cookie := &http.Cookie{
			Name:     "session-gid",
			Value:    encoded,
			Path:     "/",
			Secure:   true,
			HttpOnly: true,
		}
		http.SetCookie(w, cookie)
	}
}

// Read secure cookies in user session
func ReadCookieHandler(w http.ResponseWriter, r *http.Request) (*string, *string) {
	if cookie, err := r.Cookie("session-gid"); err == nil {
		value := make(map[string]string)
		if err = sc.Decode("cookie-name", cookie.Value, &value); err == nil {
			user := value["user"]
			token := value["token"]
			return &user, &token
		}
	}
	return nil, nil
}

// Return login page or go to post page if already logged
func getRoot(w http.ResponseWriter, r *http.Request) {
	log.WithFields(log.Fields{"request": r}).Debug("/root")
	user, _ := ReadCookieHandler(w, r)
	if user != nil {
		http.Redirect(w, r, "/post", http.StatusTemporaryRedirect)
		return
	}
	fmt.Fprintf(w, `<!doctype html><html><body><p><a href="/login">Log In</a></p></body></html>`)
}

// Return login page or go to post page if already logged
func writeHtmlError(w http.ResponseWriter, err error) {
	fmt.Fprint(w, `<!doctype html><html><body>`)
	fmt.Fprintf(w, `<p>Error: %s<p>`, err)
	fmt.Fprint(w, `<p><a href="/login">Log In</a></p>
<p><a href="#back" onClick="history.go(-1); return false;">Back</a></p>
</body>
</html>`)
}

// Redirect to Reddit for OAuth login
func handleLogin(w http.ResponseWriter, r *http.Request) {
	log.WithFields(log.Fields{"request": r}).Debug("/login")
	url := redditOauthConfig.AuthCodeURL("1", DurationTemporary)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

// Check if token is valid and if user is mod in subreddit
func validateToken(token string) (*UserResp, error) {
	req, _ := http.NewRequest("GET", "https://oauth.reddit.com/api/v1/me", nil)
	req.Header = http.Header{
		"Authorization": {"Bearer " + token},
		"User-Agent":    {useragent},
	}
	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed getting user info: %s", err.Error())
	}
	var u UserResp
	err = json.NewDecoder(res.Body).Decode(&u)
	res.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("failed getting json: %s", err.Error())
	}
	log.WithFields(log.Fields{"username": u.Name, "token": token}).Info("OAuth ok")
	req, _ = http.NewRequest("GET", "https://oauth.reddit.com/r/italy/about/moderators?limit=100", nil)
	req.Header = http.Header{
		"Authorization": {"Bearer " + token},
		"User-Agent":    {useragent},
	}
	res, err = client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed getting subreddit info: %s", err.Error())
	}
	var ms ModsResp
	err = json.NewDecoder(res.Body).Decode(&ms)
	res.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("failed getting mods json: %s", err.Error())
	}
	for _, c := range ms.Data.Children {
		// check in every moderators
		if c.Name == u.Name {
			// check if it has "all" or "mail" permission
			for _, p := range c.ModPermissions {
				if p == "all" || p == "mail" {
					log.WithFields(log.Fields{"user": u.Name, "perm": p}).Info("Mod ok")
					return &u, nil
				}
			}
		}
	}
	return nil, nil

}

// Simple reimplementation of oauth2.Config.Exchange
// Because using an User-Agent helps preventing Reddit from ratelimiting us
func ExchangeOAuth(code string) (*tokenJSON, error) {
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Add("redirect_uri", redditOauthConfig.RedirectURL)
	encodedData := data.Encode()
	req, err := http.NewRequest(http.MethodPost, redditOauthConfig.Endpoint.TokenURL, strings.NewReader(encodedData))
	if err != nil {
		return nil, err
	}
	req.Header.Add("User-Agent", useragent)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Content-Length", strconv.Itoa(len(data.Encode())))
	req.SetBasicAuth(
		url.QueryEscape(redditOauthConfig.ClientID),
		url.QueryEscape(redditOauthConfig.ClientSecret),
	)
	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	var token tokenJSON
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	err = json.Unmarshal(b, &token)
	if err != nil {
		log.WithFields(log.Fields{"response": b}).Debug("JSON error on Oauth")
		return nil, fmt.Errorf("failed getting token json: %s", err.Error())
	}
	return &token, nil
}

// Check OAuth login and return token
func validateOAuth(state string, code string) (*string, *string, error) {
	if state != "1" {
		return nil, nil, fmt.Errorf("invalid oauth state")
	}
	//token, err := redditOauthConfig.Exchange(context.Background(), code)
	token, err := ExchangeOAuth(code)
	if err != nil {
		return nil, nil, fmt.Errorf("code exchange failed: %s", err.Error())
	}
	if token == nil || token.AccessToken == "" {
		return nil, nil, fmt.Errorf("unauthorized")
	}
	u, err := validateToken(token.AccessToken)
	if u == nil {
		return nil, nil, errors.New("user not mod of r/italy")
	}
	return &u.Name, &token.AccessToken, err
}

// Build HTML for submit form
func buildSubmitForm(user string) string {
	var b strings.Builder
	b.WriteString(`<!doctype html><html><body><p>You are: `)
	b.WriteString(html.EscapeString(user))
	b.WriteString(`</p><form action='/submit' method="post">`)
	b.WriteString(`<p>URL: 
	<input 
		type='text'
		name='url'
		size='200'
		required
		pattern='https?:\/\/[\w%._\+~#=]{2,256}\.[a-z]{2,6}(?:\/.*)?'
	></p>`)
	b.WriteString(`<p>Title: <input type='text' name='title' size='200'></p>`)
	flairs, _, _ := rclient.Flair.GetPostFlairs(context.Background(), subreddit)
	if flairs != nil {
		b.WriteString(`<p>Flair: <select name='flair'>`)
		for _, flair := range flairs {
			b.WriteString(`<option value='`)
			b.WriteString(html.EscapeString(flair.ID))
			b.WriteString(`'>`)
			b.WriteString(html.EscapeString(flair.Text))
			b.WriteString(`</option>`)
		}
		b.WriteString(`</select></p>`)
	}
	b.WriteString(`<input type="submit" value="Post"> &nbsp; `)
	b.WriteString(`<button name="gettitle" type="button">Get title</button>`)
	b.WriteString(`
<script>
	function getTitle() {
		let formData = new FormData();
		formData.append("url", document.getElementsByName('url')[0].value);
		fetch(document.location.href.substr(0, document.location.href.lastIndexOf("/") + 1) + 'title',
			{method: "Post",body: formData}
		).then(resp => resp.json()
		).then(resp => document.getElementsByName('title')[0].value = resp.Title);
		return false;
	}
	window.onload = (event) => {document.getElementsByName('gettitle')[0].addEventListener("click", getTitle, true);};
</script>`)
	return b.String()

}

// Handle the OAuth login response form Reddit
func handleCallback(w http.ResponseWriter, r *http.Request) {
	log.WithFields(log.Fields{"request": r}).Debug("/callback")
	user, token, err := validateOAuth(r.FormValue("state"), r.FormValue("code"))
	if token == nil {
		if err != nil {
			log.WithError(err).Error("Error on OAuth login")
			writeHtmlError(w, err)
			return
		}
		writeHtmlError(w, errors.New("login invalid"))
		//http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}
	SetCookieHandler(w, r, *user, *token)
	http.Redirect(w, r, "/post", http.StatusTemporaryRedirect)
}

func fetchTitle(url string) (*string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	doc, err := phtml.Parse(resp.Body)
	if err != nil {
		return nil, err
	}
	var title = ""
	var findTitle func(*phtml.Node)
	findTitle = func(n *phtml.Node) {
		if title != "" {
			return
		}
		if n.Type == phtml.ElementNode && n.Data == "title" {
			title = n.FirstChild.Data
			return
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			findTitle(c)
		}
	}
	findTitle(doc)
	return &title, nil
}

type TitleReturn struct {
	Error string
	Title string
}

// Returns the form for posting
func handleGetTitle(w http.ResponseWriter, r *http.Request) {
	log.WithFields(log.Fields{"request": r}).Debug("/title")
	user, _ := ReadCookieHandler(w, r)
	url := r.FormValue("url")
	if user != nil && url != "" {
		jout := json.NewEncoder(w)
		title, err := fetchTitle(url)
		ret := TitleReturn{}
		if err != nil {
			ret.Error = err.Error()
		} else {
			ret.Title = *title
		}
		jout.Encode(ret)
		return
	}
}

// Returns the form for posting
func handlePost(w http.ResponseWriter, r *http.Request) {
	log.WithFields(log.Fields{"request": r}).Debug("/post")
	user, _ := ReadCookieHandler(w, r)
	if user != nil {
		fmt.Fprint(w, buildSubmitForm(*user))
		return
	}
	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}

// Utility method to have a False in a struct (see SubmitLink)
func newFalse() *bool {
	b := false
	return &b
}

// Post link to subreddit and redirect
func handleSubmit(w http.ResponseWriter, r *http.Request) {
	log.WithFields(log.Fields{"request": r}).Debug("/submit")
	u, _ := ReadCookieHandler(w, r)
	if u == nil {
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}
	url := strings.Trim(r.FormValue("url"), "")
	title := strings.Trim(r.FormValue("title"), "")
	flair := r.FormValue("flair")
	linkReq := reddit.SubmitLinkRequest{
		Subreddit:   subreddit,
		Title:       title,
		URL:         url,
		SendReplies: newFalse(),
	}
	if flair != "" {
		linkReq.FlairID = flair
	}
	log.WithFields(log.Fields{"post": linkReq}).Info("Posting")
	post, _, err := rclient.Post.SubmitLink(context.Background(), linkReq)
	if err != nil {
		log.WithError(err).Error("Error on Submit")
		writeHtmlError(w, err)
		return
	}
	log.WithFields(log.Fields{"user": *u, "post": post.ID}).Info("Post done")
	http.Redirect(w, r, "https://redd.it/"+post.ID, http.StatusTemporaryRedirect)
}

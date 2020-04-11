package main

import (
	"os"
	"fmt"
	"log"
	"time"
	"net/http"
	"encoding/json"
	"github.com/gorilla/mux"
	"github.com/gorilla/handlers"
	"github.com/jtblin/go-ldap-client"
	"github.com/dgrijalva/jwt-go"
)

var fn_config = "config.json"
var config Config

type Config struct {
	JwtSecret []byte `json:"jwt_secret"`
	Port int `json:"port"`
	SessionTime int `json:"session_timeout"`
	CookieDomain string `json:"cookie_domain"`

	LdapHost string `json:"ldap_host"`
	LdapPort int `json:"ldap_port"`
	LdapBindDN string `json:"ldap_binddn"`
	LdapBindPW string `json:"ldap_bindpw"`
	LdapSSL bool `json:"ldap_ssl"`
	LdapBase string `json:"ldap_base"`
	LdapUserFilter string `json:"ldap_user_filter"`
	LdapGroupFilter string `json:"ldap_group_filter"`
}

type Claims struct {
	UID string `json:"uid"`
	FirstName string `json:"fn"`
	LastName string `json:"ln"`
	Email string `json:"email"`
	jwt.StandardClaims
}

func getConfig(fn_config string) (Config, error) {
	conf := Config{}

	file, err := os.Open(fn_config)
	if err != nil {
		return conf, err
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	err = decoder.Decode(&conf)

	return conf, err
}

func AuthHandler(w http.ResponseWriter, r *http.Request) {

	// Get token
	c, err := r.Cookie("token")
	if err != nil {
		if err == http.ErrNoCookie {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		fmt.Printf("Error: %+v\n", err)
		//w.WriteHeader(http.StatusBadRequest)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	tokenString := c.Value

	// Parse token
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token)(interface{},error) {
		return config.JwtSecret, nil
	})

	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if !token.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	ret_uri := ""
	keys, ok := r.URL.Query()["returnUri"]
	if !ok || len(keys[0]) < 1 {
		ret_uri = "/"
	} else {
		ret_uri = keys[0]
	}

	host := r.Header.Get("X-Original-Host")

	log.Printf("User %s authorized to access %s%s", claims.UID, host, ret_uri)
}

func LDAPAuth(user string, pass string) (bool, map[string]string, error) {
	client := &ldap.LDAPClient {
		Base: config.LdapBase,
		Host: config.LdapHost,
		Port: config.LdapPort,
		UseSSL: config.LdapSSL,
		BindDN: config.LdapBindDN,
		BindPassword: config.LdapBindPW,
		UserFilter: config.LdapUserFilter,
		GroupFilter: config.LdapGroupFilter,
		Attributes: []string{"givenName", "sn", "mail", "uid"},
	}
	defer client.Close()

	ok, data, err := client.Authenticate(user, pass)
	return ok, data, err
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	noCookie := false
	claims := &Claims{}
	tokenString := ""

	// Get token
	c, err := r.Cookie("token")
	if err != nil {
		//if err == http.ErrNoCookie {
		//	noCookie = true
		//}
		//fmt.Printf("Error: %+v\n", err)
		noCookie = true
		//w.WriteHeader(http.StatusBadRequest)
		//w.WriteHeader(http.StatusUnauthorized)
		//return
	}

	if noCookie {
		if r.Method != "POST" {
			http.ServeFile(w, r, "static/login.html")
			return
		}

		if err := r.ParseForm(); err != nil {
			fmt.Fprintf(w, "ParseForm() err: %v", err)
			return
		}

		// TODO Input validation??

		user := r.FormValue("user")
		pass := r.FormValue("pass")

		// Try LDAP authentication
		ok, data, err := LDAPAuth(user, pass)
		if err != nil {
			log.Printf("Error: %+v", err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if !ok {
			log.Printf("Authenticating failed for user %s", user)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Success
		//log.Printf("User: %v", data)

		// Create token
		expTime := time.Now().Add(time.Duration(config.SessionTime) * time.Second)
		claims = &Claims{
			UID: data["uid"],
			FirstName: data["givenName"],
			LastName: data["sn"],
			Email: data["mail"],
			StandardClaims: jwt.StandardClaims{
				ExpiresAt: expTime.Unix(),
				IssuedAt: time.Now().Unix(),
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err = token.SignedString(config.JwtSecret)

		if err != nil {
			log.Printf("Error %+v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// Set token cookie
		http.SetCookie(w, &http.Cookie{
			Name: "token",
			Value: tokenString,
			Expires: expTime,
			Domain: config.CookieDomain,
		})

	} else {
		tokenString = c.Value

		// Parse token
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token)(interface{},error) {
			return config.JwtSecret, nil
		})

		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		if !token.Valid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Success
	}

	// Response
	ret_uri := ""
	keys, ok := r.URL.Query()["returnUri"]
	if !ok || len(keys[0]) < 1 {
		ret_uri = "/"
	} else {
		ret_uri = keys[0]
	}

	host := r.Header.Get("X-Original-Host")

	// Service-specific login routines
	switch host {
		// Faking (?) GitLab's OmniAuth JWT
		case "gitlab.example.com":
			log.Printf("User %s logging into gitlab", claims.UID)

			if ret_uri == "/" {
				// Old method to just redirect to callback, which would then redirect to /
				ret_uri = "/users/auth/jwt/callback?jwt="+tokenString
			} else {
				// Make a subrequest to /users/auth/jwt/callback for session cookie
				client := &http.Client {
					CheckRedirect: func(r *http.Request, via []*http.Request) error {
						return http.ErrUseLastResponse
					},
				}
				resp, err := client.Get("https://"+host+"/users/auth/jwt/callback?jwt="+tokenString)
				if err != nil {
					//log.Printf("Error: %+v", err)
				}

				// Set the session cookie
				for _, cookie := range resp.Cookies() {
					//log.Printf("Cookie %+v", cookie)
					http.SetCookie(w, cookie)
				}
			}
	}

	log.Printf("User %s authorized to access %s", claims.UID, host)
	http.Redirect(w, r, "https://"+host+ret_uri, http.StatusSeeOther)

}

func main() {

	// Open and read configuration
	c, err := getConfig(fn_config)
	if err != nil {
		log.Fatalf("Error %v", err)
	}
	config = c

	log.Printf("Configuration loaded from file \"%s\"", fn_config)
	//log.Printf("Configuration: %+v", config)

	// Set up HTTP routers
	r := mux.NewRouter()
	r.HandleFunc("/login", LoginHandler)
	r.HandleFunc("/auth", AuthHandler)
	logger := handlers.LoggingHandler(os.Stdout, r)

	log.Printf("Starting HTTP server listening on port %d", config.Port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", config.Port), logger))
}

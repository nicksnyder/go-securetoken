package main

import (
	"html/template"
	"log"
	"net/http"
	"time"

	"github.com/nicksnyder/go-securetoken/securetoken"
)

var unsafeKey = []byte("1234567887654321")
var tokener *securetoken.Tokener
var cookieName = "session"

func main() {
	http.HandleFunc("/", handleHome)
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/logout", handleLogout)

	var err error
	tokener, err = securetoken.NewTokener(unsafeKey, 24*time.Hour)
	if err != nil {
		panic(err)
	}

	log.Println("Demo running at http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

var homeTemplate = template.Must(template.New("").Parse(`
<!DOCTYPE html>
<html>
	<head></head>
	<body>
		{{if .Email}}
			<p>Token: {{.Token}}</p>
			<p>You are signed in as {{.Email}}</p>
			<form action="logout" method="POST">
				<input type="submit" value="Logout"/>
			</form>
		{{else}}
			<form action="login" method="POST">
				Email: <input type="email" name="email" />
				<input type="submit" value="Login"/>
			</form>
		{{end}}
	</body>
</html>
`))

func handleHome(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(cookieName)
	if err != nil {
		homeTemplate.Execute(w, nil)
		return
	}
	email, err := tokener.UnsealString(c.Value)
	if err != nil {
		panic(err)
	}
	homeTemplate.Execute(w, map[string]string{
		"Token": c.Value,
		"Email": string(email),
	})
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")
	token, err := tokener.SealString(email)
	if err != nil {
		panic(err)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    token,
		HttpOnly: true,
	})
	http.Redirect(w, r, "/", http.StatusFound)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Expires:  time.Unix(1, 0),
		HttpOnly: true,
	})
	http.Redirect(w, r, "/", http.StatusFound)
}

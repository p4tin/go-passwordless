package main

/*
 *
 *	go-passwordless
 *
 *	- remove echo for gorilla/mux
 *	- Validate
 *	- Make it prettier
 *	- Use Redis for profile data and tokens
 *
 */
import (
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/smtp"
	"strings"
	"time"

	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
	"encoding/hex"
)

var authemail map[string]string

var letterRunes = []rune("1234567890")
var key []byte
var salt string = "ThisIsTheSalt"

var cookieDurationInHours int = 3

func init() {
	log.SetFormatter(&log.JSONFormatter{})
	authemail = make(map[string]string)
	content, err := ioutil.ReadFile("./aes.key")
	if err != nil {
		log.Fatalln("Could not read key file (aes.key)")
	}
	key, err = base64.StdEncoding.DecodeString(string(content))
	if err != nil {
		log.Fatalln("Could not decode base64 key from file (aes.key)")
	}
}

func encrypt(key, text []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	b := base64.StdEncoding.EncodeToString(text)
	ciphertext := make([]byte, aes.BlockSize+len(b))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(crand.Reader, iv); err != nil {
		return nil, err
	}
	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], []byte(b))
	return ciphertext, nil
}

func decrypt(key, text []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(text) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}
	iv := text[:aes.BlockSize]
	text = text[aes.BlockSize:]
	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(text, text)
	data, err := base64.StdEncoding.DecodeString(string(text))
	if err != nil {
		return nil, err
	}
	return data, nil
}

func generateLoginToken() string {
	b := make([]rune, 6)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

func generateAuthenticatedToken(email string) string {
	token, err := encrypt(key, []byte(email+"||"+salt))
	if err == nil {
		return hex.EncodeToString(token)
	} else {
		return ""
	}
}

/*** Handler ***/
type AppHandler struct{}

// Our appHandler type will now satisify http.Handler
func (fn AppHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	t, err := template.ParseFiles("static/index.html")
	if err != nil {
		log.Println(err)
	}
	t.Execute(w, "Hello World!")
}

/*** Handler ***/
type LoginFormHandler struct{}

func (fn LoginFormHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	t, err := template.ParseFiles("static/login.html")
	if err != nil {
		log.Println(err)
	}
	t.Execute(w, "")
}

/*** Handler ***/
type SendEmailHandler struct{}

func (fn SendEmailHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	token := generateLoginToken()
	email := r.FormValue("email")
	log.Println("Sending login email to ", email)
	authemail[email] = token
	fmt.Printf("Sending Email: %+v\n", authemail)
	sendEmail(email, token)

	t, err := template.ParseFiles("static/token.html")
	if err != nil {
		log.Println(err)
	}
	t.Execute(w, email)
}

/*** Handler ***/
type ConfirmHandler struct{}

func (fn ConfirmHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	token := vars["token"]
	email := vars["email"]
	fmt.Println("Confirm Token:", email, "/", token)
	fmt.Printf("Confirm Token: %+v\n", authemail)
	if val, ok := authemail[email]; ok {
		if val != token {
			log.Println("1 - Not Authorized!!")
			t, err := template.ParseFiles("static/token.html")
			if err != nil {
				log.Println(err)
			}
			t.Execute(w, email)
			return
		} else {
			cookie := &http.Cookie{
				Name:  "login.token",
				Value: generateAuthenticatedToken(email),
				Path:  "/",
				Expires: time.Now().Add(time.Hour * time.Duration(cookieDurationInHours)),
			}
			http.SetCookie(w, cookie)
			http.Redirect(w, r, "/profile", 302)
		}
	} else {
		log.Println("2 - Not Authorized!!")
		t, err := template.ParseFiles("static/token.html")
		if err != nil {
			log.Println(err)
		}
		t.Execute(w, email)
		return
	}
}

/*** Handler ***/
type ProfileHandler struct{}

func (fn ProfileHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	t, err := template.ParseFiles("static/profile.html")
	if err != nil {
		log.Println(err)
	}
	t.Execute(w, "")
}

func sendEmail(email, token string) {
	from := "pfort69@gmail.com"
	pass := "iv17wt0c"
	to := email

	// Add MIME-Version and Content-type
	msg := "From: " + from + "\r\n" +
		"To: " + to + "\r\n" +
		"MIME-Version: 1.0" + "\r\n" +
		"Content-type: text/html" + "\r\n" +
		"Subject: Your messages subject" + "\r\n\r\n" +
		"To complete your login visit <a href=\"http://localhost:8080/auth/confirm/" + email + "/" + token + "\">this link</a>" + "\r\n"

	err := smtp.SendMail("smtp.gmail.com:587",
		smtp.PlainAuth("", from, pass, "smtp.gmail.com"),
		from, []string{to}, []byte(msg))

	if err != nil {
		log.Printf("smtp error: %s", err)
		return
	}
}

/*** Validate Session Middleware ***/

func Validate(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, err := r.Cookie("login.token")
		if err != nil {
			log.Println("3 - Not Authorized!!")
			http.Redirect(w, r, "/login-form", 302)
			return
		}
		fmt.Println("Validate:", token.Value)
		b, err := hex.DecodeString(token.Value)
		if err != nil {
			log.Println("3.5 Not Authorized", err)
			http.Redirect(w, r, "/login-form", 302)
			return
		}
		text, err := decrypt(key, b)
		if err != nil {
			log.Println("4 - Not Authorized!!", err)
			http.Redirect(w, r, "/login-form", 302)
			return
		}
		userInfo := strings.Split(string(text), "||")
		log.Println("you are logged in as: ", userInfo[0])
		h.ServeHTTP(w, r)
	})
}

func main() {
	addr := "0.0.0.0:8080"

	r := mux.NewRouter()

	r.Handle("/login-form", LoginFormHandler{}).Methods("GET")
	r.Handle("/auth/confirm/{email}/{token}", ConfirmHandler{}).Methods("GET")
	r.Handle("/auth/email", SendEmailHandler{}).Methods("POST")
	r.Handle("/profile", Validate(ProfileHandler{})).Methods("GET")
	r.Handle("/", AppHandler{}).Methods("GET")

	server := &http.Server{
		Handler: r,
		Addr:    addr,
		// Good practice: enforce timeouts for servers you create!
		WriteTimeout: 5 * time.Second,
		ReadTimeout:  5 * time.Second,
	}

	log.Println("Server Listening on", addr)
	server.ListenAndServe()
}

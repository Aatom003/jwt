package main

import (
	"encoding/json" // package for encoding and decoding JSON data
	"net/http"      // package for building HTTP servers and clients
	"time"          // package for working with time and dates

	"github.com/dgrijalva/jwt-go" // package for working with JSON Web Tokens (JWTs)
)

var jwtKey = []byte("secret_key")               // secret key used to sign the JWT

var users = map[string]string{                  // map of user names and passwords
	 "user1":"password1",
	 "user3":"password3" ,
}

// Credentials struct represents the user credentials (username and password) sent in the request body
type Credentials struct{
	UserName string `json:"username"`            // field for the user name
	PassWord string `json:"password"`            // field for the password
}

// Claims struct represents the claims (information) stored in the JWT
type Claims struct {
	UserName string `json:"username"`            // field for the user name
	jwt.StandardClaims                           // embedded field for the standard JWT claims (expires at, etc.)
}

// Login function handles the login request and generates a JWT for the user
func Login(w http.ResponseWriter, r *http.Request) {
    // decode the credentials from the request body
	var credentials Credentials
	err := json.NewDecoder(r.Body).Decode(&credentials)
	if err != nil{                              // check for decoding error
		 w.WriteHeader(http.StatusBadRequest)    // return Bad Request status
		 return
	}
	// get the password for the given user name from the users map
	password,ok := users[credentials.UserName]

	if !ok   || password != credentials.PassWord{  // check if the user name or password is incorrect
		w.WriteHeader(http.StatusUnauthorized)     // return Unauthorized status
		return 
	}
	// set the expiration time for the JWT to 5 minutes from now
	expirationTime := time.Now().Add(time.Minute*5)
 
	// create a new Claims struct with the user name and expiration time
	claims := &Claims{
		UserName: credentials.UserName, 
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	// create a new JWT using the HS256 signing method and the Claims struct as the payload
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	// sign the JWT using the jwtKey and encode it as a string
	tokenString, err := token.SignedString(jwtKey)

	if err != nil {                              // check for signing error
		w.WriteHeader(http.StatusInternalServerError) // return Internal Server Error status
		return
	}
	// set the JWT as a cookie in the response
	http.SetCookie(w,
		&http.Cookie{
			Name:    "token",
			Value:   tokenString,
			Expires: expirationTime,
		})
}

// Refresh function handles the refresh request and generates a new JWT for the user
func Refresh(w http.ResponseWriter, r *http.Request) {
    
}

// Home function handles the home request and returns a message to the user
func Home(w http.ResponseWriter, r *http.Request) {
    
}
 
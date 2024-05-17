package main

import (
	"database/sql"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/golang-jwt/jwt/v4"
	"log"
	"net/http"
	"time"

	_ "github.com/lib/pq"
)

type User struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

var db *sql.DB
var jwtKey = []byte("secret")

type Claims struct {
	Email string `json:"email"`
	jwt.StandardClaims
}

func main() {
	var err error
	db, err = sql.Open("postgres", "user=rendy dbname=rendy password=rendyeka sslmode=disable")
	if err != nil {
		log.Fatal("error opening db", err)
	}

	defer db.Close()

	router := gin.Default()

	// router.Use(authMiddleware)
	router.POST("/login", authMiddleware, loginUser)

	router.POST("/register", registerUser)

	router.Run(":8080")
}

func loginUser(c *gin.Context) {
	// init for save from json
	var user User

	if err := c.BindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	}

	validate := validator.New()
	if err := validate.Struct(user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var dbPassword string
	err := db.QueryRow("SELECT password FROM users WHERE email = $1", user.Email).Scan(&dbPassword)

	// if email doesnt exist
	// return err unauthorized
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	// if password not equal
	// return err unauthorized
	if user.Password != dbPassword {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	// make expiration time for token
	expirationTime := time.Now().Add(60 * time.Minute)
	claims := &Claims{
		Email: user.Email,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	// created new token and signed with jwtkey
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// c.SetCookie("token", tokenString, 3600, "/", "localhost", false, true)

	c.JSON(http.StatusOK, gin.H{"data": tokenString})
}

func authMiddleware(c *gin.Context) {
	tokenString := c.GetHeader("Authorization")

	if tokenString == "" {
		c.Next()
		return
	}

	claims := &Claims{}

	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	if err != nil || !token.Valid {
		fmt.Println("token tidak valid")
		c.Next()
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": fmt.Sprintf("welcome %s", claims.Email)})
	c.Abort()
}

func registerUser(c *gin.Context) {
	var user User

	if err := c.BindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	}

	validate := validator.New()
	if err := validate.Struct(user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	_, err := db.Exec("INSERT INTO users (email, password) VALUES ($1, $2)", user.Email, user.Password)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "user created successfully"})
}

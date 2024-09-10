package main

import (
	"crypto/rand"
	"database/sql"
	"fmt"
	"log"
	"myapp/templates"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/a-h/templ"
	"github.com/golang-jwt/jwt/v5"
	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	_ "github.com/mattn/go-sqlite3"
)

// jwtCustomClaims are custom claims extending default ones.
// See https://github.com/golang-jwt/jwt for more examples

type jwtCustomClaims struct {
	Email string `json:"name"`
	Admin bool   `json:"admin"`
	jwt.RegisteredClaims
}

func randomSecret(length uint32) ([]byte, error) {
	secret := make([]byte, length)

	_, err := rand.Read(secret)
	if err != nil {
		return nil, err
	}
	return secret, nil
}

func register(c echo.Context) error {
	email := c.FormValue("email")
	password := c.FormValue("password")
	passwordRepeat := c.FormValue("passwordRepeat")

	if password != passwordRepeat {
		return c.String(http.StatusOK, "Passwords dont match")
	}
	argon2IDHash := NewArgon2idHash(1, 32, 64*1024, 32, 256)

	hashSalt, err := argon2IDHash.GenerateHash([]byte(password), nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	query := "INSERT INTO users (email, hash2, salt2, hash, salt, date_created, date_updated, admin) VALUES (?, ?, ?, 'hash', 'salt', datetime('now'), datetime('now'), 'true');"

	const file string = "./database/database.db"
	db, err := sql.Open("sqlite3", file)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	stmt, err := db.Prepare(query)
	if err != nil {
		log.Fatal(err)
	}
	defer stmt.Close()
	if _, err := stmt.Exec(email, string(hashSalt.Hash), string(hashSalt.Salt)); err != nil {
		log.Fatal(err)
	}
	c.Response().Header().Set("HX-Redirect", "/login")
	// Return a successful response
	return c.NoContent(http.StatusOK)
	// return c.String(http.StatusOK, "Registered")
}

func login(c echo.Context) error {
	argon2IDHash := NewArgon2idHash(1, 32, 64*1024, 32, 256)
	email := c.FormValue("email")
	password := c.FormValue("password")
	// Search for email record
	const file string = "./database/database.db"
	db, err := sql.Open("sqlite3", file)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	rows, err := db.Query("SELECT * FROM users WHERE email = ?", email)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var id int
		var email string
		var hash2 string
		var salt2 string
		var hash string
		var salt string
		var date_created string
		var date_updated string
		var admin string
		err = rows.Scan(&id, &email, &hash, &salt, &date_created, &date_updated, &admin, &hash2, &salt2)
		if err != nil {
			log.Fatal(err)
		}
		err = argon2IDHash.Compare([]byte(hash2), []byte(salt2), []byte(password))
		if err != nil {
			// Throws unauthorized error
			return echo.ErrUnauthorized
		}
		fmt.Println("argon2IDHash Password and Hash match")
	}

	// Set custom claims
	claims := &jwtCustomClaims{
		email,
		true,
		jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 72)),
		},
	}

	// Create token with claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Generate encoded token and send it as response.
	t, err := token.SignedString([]byte("secret"))
	if err != nil {
		return err
	}
	cookie := new(http.Cookie)
	cookie.Name = "JWTToken"
	cookie.Value = t
	cookie.Expires = time.Now().Add(time.Hour * 72)
	cookie.HttpOnly = true
	cookie.Secure = true // Ensure this is true when serving over HTTPS
	c.SetCookie(cookie)
	c.Response().Header().Set("HX-Redirect", "/")
	// Return a successful response
	return c.NoContent(http.StatusOK)
	// return c.Redirect(http.StatusSeeOther, "/login")
}
func logout(c echo.Context) error {
	cookie := new(http.Cookie)
	cookie.Name = "JWTToken"
	cookie.Value = ""
	cookie.Expires = time.Now().Add(-time.Hour)
	cookie.HttpOnly = true
	cookie.Secure = true // Ensure this is true when serving over HTTPS
	c.SetCookie(cookie)
	return c.Redirect(http.StatusSeeOther, "/login")
}

func jwtFromCookie(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		cookie, err := c.Cookie("JWTToken")
		if err != nil {
			return next(c)
		}
		c.Request().Header.Set("Authorization", "Bearer "+cookie.Value)
		return next(c)
	}
}

func restricted(c echo.Context) error {
	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(*jwtCustomClaims)
	name := claims.Email
	return c.String(http.StatusOK, "Welcome "+name+"!")
}

func database(command string) {
	const file string = "./database/database.db"
	db, err := sql.Open("sqlite3", file)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	rows, err := db.Query(command)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var id int
		var weight string
		var hydration string
		var number string
		var starter string
		var salt string
		var owner_id int
		err = rows.Scan(&id, &weight, &hydration, &number, &starter, &salt, &owner_id)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(id, weight, hydration, salt, starter, number)
	}
	err = rows.Err()
	if err != nil {
		log.Fatal(err)
	}
}
func optionalJwtMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		// Try to extract the JWT token from the request
		// token, err := echojwt.FromContext(c)
		token, err := c.Cookie("JWTToken")
		if err == nil && token != nil {
			// If the token is present, parse it
			claims, err := jwt.ParseWithClaims(token.Value, new(jwtCustomClaims), func(token *jwt.Token) (interface{}, error) {
				return []byte("secret"), nil
			})
			if err == nil && claims.Valid {
				// If the token is valid, store the user info in the context
				c.Set("user", claims)
			}
		}
		// Pass the request to the next handler
		return next(c)
	}
}
func profileHandler(c echo.Context) error {
	user := c.Get("user")
	if user == nil {
		return c.Redirect(http.StatusSeeOther, "/login")
	}
	claims := user.(*jwt.Token).Claims.(*jwtCustomClaims)
	name := claims.Email
	return Render(c, http.StatusOK, templates.Profile(name))
}

func recipesHandler(c echo.Context) error {
	m := make(map[string]string)
	n := make(map[string]string, 0)
	user := c.Get("user")
	var email string
	var owner_id int
	if user != nil {
		user := c.Get("user").(*jwt.Token)
		claims := user.Claims.(*jwtCustomClaims)
		email = claims.Email
		println(email)
	}
	const file string = "./database/database.db"
	db, err := sql.Open("sqlite3", file)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	_, err = db.Exec("PRAGMA foreign_keys = ON")
	if err != nil {
		log.Fatal(err)
	}
	// Get user data from the database
	rows, err := db.Query("SELECT * FROM users WHERE email = ?", email)
	if err != nil {
		// Handle the error
		panic(err)
	}
	defer rows.Close()

	for rows.Next() {
		var id int
		var email string
		var hash []byte
		var dateCreated string
		var dateUpdated string
		var admin string
		var salt []byte
		var hash2 string
		var salt2 string

		err := rows.Scan(&id, &email, &hash, &dateCreated, &dateUpdated, &admin, &salt, &hash2, &salt2)
		if err != nil {
			// Handle the error
			panic(err)
		}
		owner_id = id
	}

	query := "SELECT * FROM sourdough_pizza WHERE owner_id=?;"
	rows, err = db.Query(query, owner_id)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var id int
		var weight string
		var hydration string
		var number string
		var starter string
		var salt string
		var owner_id int
		err = rows.Scan(&id, &weight, &hydration, &number, &starter, &salt, &owner_id)
		if err != nil {
			log.Fatal(err)
		}
		m["id"] = string(id)
		m["weight"] = weight
		m["hydration"] = hydration
		m["number"] = number
		m["starter"] = starter
		m["salt"] = salt

		n = append(n, m)
		fmt.Println(id, weight, hydration, salt, starter, number)
	}
	err = rows.Err()
	if err != nil {
		log.Fatal(err)
	}
	println(m)
	return Render(c, http.StatusOK, templates.SavedRecipes(m))
}

func main() {
	if _, err := os.Stat("./database/database.db"); err == nil {
		println("database found")
	} else {
		println("database not found, creating database ...")
		err := os.MkdirAll("database", 0750)
		if err != nil {
			log.Fatal(err)
		}
		os.Create("./database/database.db")
	}
	db, err := sql.Open("sqlite3", "./database/database.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	// CREATE USERS TABLE
	mainQuery := "CREATE TABLE if not exists users (id INTEGER PRIMARY KEY, email TEXT, hash BLOB, date_created TEXT, date_updated TEXT, admin TEXT, salt BLOB, hash2 TEXT, salt2 TEXT);"
	_, err = db.Exec(mainQuery)
	if err != nil {
		log.Printf("%q: %s\n", err, mainQuery)
		return
	}
	// CREATE SOURDOUGH PIZZA TABLE
	sourdoughPizzaQuery := "CREATE TABLE IF NOT EXISTS sourdough_pizza (id INTEGER PRIMARY KEY, starter INTEGER, number INTEGER, weight INTEGER, hydration INTEGER, salt INTEGER, owner_id INTEGER, FOREIGN KEY(owner_id) REFERENCES users(id) ON DELETE CASCADE);"
	_, err = db.Exec(sourdoughPizzaQuery)
	if err != nil {
		log.Printf("%q: %s\n", err, sourdoughPizzaQuery)
		return
	}
	e := echo.New()
	// e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.POST("/login", login)
	e.GET("/login", loginGET)
	e.POST("/register", register)
	e.GET("/register", registerGET)
	e.GET("/logout", logout)
	e.GET("/profile", profileHandler)
	r := e.Group("/restricted")
	// Configure middleware with the custom claims type
	config := echojwt.Config{
		NewClaimsFunc: func(c echo.Context) jwt.Claims {
			return new(jwtCustomClaims)
		},
		SigningKey: []byte("secret"),
	}
	r.Use(echojwt.WithConfig(config))
	e.Use(jwtFromCookie)
	// e.Use(echojwt.WithConfig(config))
	e.Use(optionalJwtMiddleware)
	r.GET("", restricted)
	e.GET("/", HomeHandler)
	e.GET("/about", AboutHandler)
	e.GET("/saved-recipes", recipesHandler)
	e.GET("/recipe/sourdough-pizza", SourdoughPizzaRecipeGET)
	e.POST("/recipe/sourdough-pizza", SourdoughPizzaPOST)
	e.POST("/recipe/sourdough-pizza-save", SourdoughPizzaSavePOST)
	e.Static("/static", "static")
	e.File("/favicon.ico", "static/favicon/favicon.ico")
	e.Logger.Fatal(e.Start(":1324"))
}

func Render(ctx echo.Context, statusCode int, t templ.Component) error {
	buf := templ.GetBuffer()
	defer templ.ReleaseBuffer(buf)
	if err := t.Render(ctx.Request().Context(), buf); err != nil {
		return err
	}
	return ctx.HTML(statusCode, buf.String())
}

func HomeHandler(c echo.Context) error {
	user := c.Get("user")
	if user != nil {
		user := c.Get("user").(*jwt.Token)
		claims := user.Claims.(*jwtCustomClaims)
		name := claims.Email
		println(name)
	}
	return Render(c, http.StatusOK, templates.Home())
}
func loginGET(c echo.Context) error {
	_, err := c.Cookie("JWTToken")
	if err != nil {
		println("no cookie found, please login")
		// If cookie is missing, redirect to register
	} else {
		return c.Redirect(http.StatusSeeOther, "/")
		// user := c.Get("user").(*jwt.Token)
		// claims := user.Claims.(*jwtCustomClaims)
		// name := claims.Email
		// println(name)
	}
	return Render(c, http.StatusOK, templates.Login())
}
func registerGET(c echo.Context) error {
	return Render(c, http.StatusOK, templates.Register())
}
func AboutHandler(c echo.Context) error {
	return Render(c, http.StatusOK, templates.About())
}
func SourdoughPizzaRecipeGET(c echo.Context) error {
	database("SELECT * FROM sourdough_pizza;")
	return Render(c, http.StatusOK, templates.Recipe())
}
func SourdoughPizzaPOST(c echo.Context) error {
	starter, err := strconv.ParseFloat(c.FormValue("starter"), 32)
	if err != nil {
		// ... handle error
		panic(err)
	}
	number, err := strconv.ParseFloat(c.FormValue("number"), 32)
	if err != nil {
		// ... handle error
		panic(err)
	}
	weight, err := strconv.ParseFloat(c.FormValue("weight"), 32)
	if err != nil {
		// ... handle error
		panic(err)
	}
	hydration, err := strconv.ParseFloat(c.FormValue("hydration"), 32)
	if err != nil {
		// ... handle error
		panic(err)
	}
	salt, err := strconv.ParseFloat(c.FormValue("salt"), 32)
	if err != nil {
		// ... handle error
		panic(err)
	}

	total_weight := weight * number
	starter_water := starter / 2
	starter_flour := starter / 2
	// total weight = total_flour + total_water + salt
	// total weight = total flour + total flour*hydration + salt*saltpercentage
	total_flour := total_weight / (hydration/100 + 1 + salt/100)
	total_water := total_flour * (hydration / 100)
	added_water := total_water - starter_water
	added_flour := total_flour - starter_flour
	added_salt := total_flour * salt / 100

	if total_weight < starter {
		return c.String(http.StatusOK, "Too Much Sourdough Starter :(")
	}
	return Render(c, http.StatusOK, templates.SourdoughPizzaForm(added_flour, added_water, added_salt, starter, number, weight, hydration, salt))
}

func SourdoughPizzaSavePOST(c echo.Context) error {
	user := c.Get("user")
	var email string
	var owner_id int
	if user != nil {
		user := c.Get("user").(*jwt.Token)
		claims := user.Claims.(*jwtCustomClaims)
		email = claims.Email
		println(email)
	}
	const file string = "./database/database.db"
	db, err := sql.Open("sqlite3", file)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	_, err = db.Exec("PRAGMA foreign_keys = ON")
	if err != nil {
		log.Fatal(err)
	}

	// Get user data from the database
	rows, err := db.Query("SELECT * FROM users WHERE email = ?", email)
	if err != nil {
		// Handle the error
		panic(err)
	}
	defer rows.Close()

	for rows.Next() {
		var id int
		var email string
		var hash []byte
		var dateCreated string
		var dateUpdated string
		var admin string
		var salt []byte
		var hash2 string
		var salt2 string

		err := rows.Scan(&id, &email, &hash, &dateCreated, &dateUpdated, &admin, &salt, &hash2, &salt2)
		if err != nil {
			// Handle the error
			panic(err)
		}
		owner_id = id
		// Process the user data
		// ...
	}

	starter, err := strconv.ParseFloat(c.FormValue("starter"), 32)
	if err != nil {
		// ... handle error
		panic(err)
	}
	number, err := strconv.ParseFloat(c.FormValue("number"), 32)
	if err != nil {
		// ... handle error
		panic(err)
	}
	weight, err := strconv.ParseFloat(c.FormValue("weight"), 32)
	if err != nil {
		// ... handle error
		panic(err)
	}
	hydration, err := strconv.ParseFloat(c.FormValue("hydration"), 32)
	if err != nil {
		// ... handle error
		panic(err)
	}
	salt, err := strconv.ParseFloat(c.FormValue("salt"), 32)
	if err != nil {
		// ... handle error
		panic(err)
	}

	total_weight := weight * number
	starter_water := starter / 2
	starter_flour := starter / 2
	// total weight = total_flour + total_water + salt
	// total weight = total flour + total flour*hydration + salt*saltpercentage
	total_flour := total_weight / (hydration/100 + 1 + salt/100)
	total_water := total_flour * (hydration / 100)
	added_water := total_water - starter_water
	added_flour := total_flour - starter_flour
	added_salt := total_flour * salt / 100
	println(added_water)
	println(added_flour)
	println(added_salt)

	if total_weight < starter {
		return c.String(http.StatusOK, "Too Much Sourdough Starter :(")
	}

	query := "INSERT INTO sourdough_pizza(starter, number, weight, hydration, salt, owner_id) values(?, ?, ?, ?, ?, ?)"
	stmt, err := db.Prepare(query)
	if err != nil {
		log.Fatal(err)
	}
	defer stmt.Close()
	if _, err := stmt.Exec(starter, number, weight, hydration, salt, owner_id); err != nil {
		log.Fatal(err)
	}
	// return Render(c, http.StatusOK, templates.SourdoughPizzaForm(added_flour, added_water, added_salt, starter, number, weight, hydration, salt))
	return c.String(http.StatusOK, "Saved!")
}

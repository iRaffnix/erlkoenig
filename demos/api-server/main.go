package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
)

var dbURL string

func main() {
	port := "8080"
	dbURL = "http://10.0.0.30:4001"

	if len(os.Args) > 1 {
		port = os.Args[1]
	}
	if len(os.Args) > 2 {
		dbURL = os.Args[2]
	}

	http.HandleFunc("/api/users", handleUsers)
	http.HandleFunc("/api/health", handleHealth)
	http.HandleFunc("/", handleRoot)

	log.Printf("api-server listening on :%s, db=%s", port, dbURL)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("error: %v", err)
	}
}

func handleRoot(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]interface{}{
		"service":   "erlkoenig-api",
		"endpoints": []string{"/api/users", "/api/health"},
	})
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	resp, err := http.Get(dbURL + "/status")
	if err != nil {
		writeJSON(w, map[string]interface{}{"status": "unhealthy", "error": err.Error()})
		return
	}
	defer resp.Body.Close()
	writeJSON(w, map[string]interface{}{"status": "healthy", "db": dbURL})
}

func handleUsers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		getUsers(w, r)
	case "POST":
		createUser(w, r)
	default:
		http.Error(w, "method not allowed", 405)
	}
}

func getUsers(w http.ResponseWriter, r *http.Request) {
	result, err := dbQuery(`SELECT * FROM users`)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	writeJSON(w, result)
}

func createUser(w http.ResponseWriter, r *http.Request) {
	var user struct {
		Name  string `json:"name"`
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "invalid JSON", 400)
		return
	}

	stmt := fmt.Sprintf(`INSERT INTO users(name, email) VALUES("%s", "%s")`,
		strings.ReplaceAll(user.Name, `"`, `""`),
		strings.ReplaceAll(user.Email, `"`, `""`))

	result, err := dbExecute(stmt)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.WriteHeader(201)
	writeJSON(w, result)
}

func dbQuery(sql string) (interface{}, error) {
	body, _ := json.Marshal([]string{sql})
	resp, err := http.Post(dbURL+"/db/query?pretty", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	var result interface{}
	json.Unmarshal(data, &result)
	return result, nil
}

func dbExecute(sql string) (interface{}, error) {
	body, _ := json.Marshal([]string{sql})
	resp, err := http.Post(dbURL+"/db/execute?pretty", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	var result interface{}
	json.Unmarshal(data, &result)
	return result, nil
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

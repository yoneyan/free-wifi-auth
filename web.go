package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strings"
)

/*
func sayhelloName(w http.ResponseWriter, r *http.Request) {
	r.ParseForm() //urlが渡すオプションを解析します。POSTに対してはレスポンスパケットのボディを解析します（request body）
	//注意：もしParseFormメソッドがコールされなければ、以下でフォームのデータを取得することができません。
	fmt.Println(r.Form) //これらのデータはサーバのプリント情報に出力されます
	fmt.Println("path", r.URL.Path)
	fmt.Println("scheme", r.URL.Scheme)
	fmt.Println(r.Form["url_long"])
	for k, v := range r.Form {
		fmt.Println("key:", k)
		fmt.Println("val:", strings.Join(v, ""))
	}
	fmt.Fprintf(w, "Hello astaxie!") //ここでwに書き込まれたものがクライアントに出力されます。
}
*/

func login(w http.ResponseWriter, r *http.Request) {
	fmt.Println("-----------web-----------")
	fmt.Println("method:", r.Method)
	fmt.Printf("Req: %s %s\n", r.Host, r.URL.Path)
	if r.Host == "captive.apple.com" {
		http.Redirect(w, r, "http://wifi-auth.local/", 301)
	}

	client := r.Header.Get("X-Real-Ip")
	if client == "" {
		client = r.Header.Get("X-Forwarded-For")
	}
	if client == "" {
		client = r.RemoteAddr
	}

	string_count := strings.Index(client, ":")
	client_ip := client[:string_count]
	client_port := client[string_count+1:]

	if r.Method == "GET" {
		t, _ := template.ParseFiles("index.html")
		t.Execute(w, nil)
	} else {
		r.ParseForm()
		user := r.Form["username"]
		pass := r.Form["password"]
		fmt.Println("username:", user[0])
		fmt.Println("password:", pass[0])

		fmt.Println("ClientIP: " + client_ip)
		fmt.Println("ClientPort: " + client_port)

		auth_result := verifyauth(client_ip, user[0], pass[0])
		fmt.Println(auth_result)
		if auth_result {
			w.Write([]byte("OK!!"))
		} else {
			w.Write([]byte("NG!!"))
		}
	}
}

//func permit(w http.ResponseWriter, r *http.Request) {
//	r.ParseForm()
//	fmt.Println(r.Form)
//	fmt.Println("Host", r.Host)
//	fmt.Println("path", r.URL.Path)
//	fmt.Println("scheme", r.URL.Scheme)
//	fmt.Println(r.Form["url_long"])
//	for k, v := range r.Form {
//		fmt.Println("key:", k)
//		fmt.Println("val:", strings.Join(v, ""))
//	}
//	fmt.Fprintf(w, "OK!")
//
//}

func ReadUserIP(r *http.Request) string {
	IPAddress := r.Header.Get("X-Real-Ip")
	if IPAddress == "" {
		IPAddress = r.Header.Get("X-Forwarded-For")
	}
	if IPAddress == "" {
		IPAddress = r.RemoteAddr
	}
	return IPAddress
}

func RedirectHandler(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "http://wifi-auth.local/", 301)
	fmt.Println("-----------redirect-----------")
	fmt.Printf("Req: %s %s\n", r.Host, r.URL.Path)
	fmt.Println("redirect now")
}

func webserver() {
	http.HandleFunc("/", login)
	http.HandleFunc("/rd", RedirectHandler)
	http.HandleFunc("/hotspot-detect.html", RedirectHandler
	http.HandleFunc("/generate_204", RedirectHandler)

	//http.HandleFunc("/test", permit)

	err := http.ListenAndServe(":80", nil)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}

}

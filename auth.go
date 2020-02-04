package main

func verifyauth(ip, user, pass string) bool {
	if user == "test" && pass == "test" {
		recordclient(ip)
		return true
	}
	if user == "" && pass == "" {
		recordclient(ip)
		return true
	}
	return false
}

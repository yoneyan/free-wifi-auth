package main

func verifyauth(ip, user, pass string) bool {
	if user == "test" && pass == "test" {
		return true
	}
	return false
}

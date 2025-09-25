package main

import (
	"fmt"
	"log"
	"os"
	"time"

	mega "github.com/t3rm1n4l/go-mega"
)

func main() {
	// Get credentials from environment variables or use defaults for testing
	email := os.Getenv("X_MEGA_USER")
	password := os.Getenv("X_MEGA_PASSWORD")
	fmt.Printf("Using email: %s\n", email)

	// Create a new Mega client with debugging enabled
	m := mega.New()

	// Enable debug logging to see the hashcash flow if it happens
	m.SetDebugger(func(format string, v ...interface{}) {
		log.Printf("[DEBUG] "+format, v...)
	})

	m.SetLogger(func(format string, v ...interface{}) {
		log.Printf("[INFO] "+format, v...)
	})

	fmt.Println("Testing Mega API connection with hashcash support...")
	fmt.Println("This will attempt to login and perform some basic operations.")
	fmt.Println("If the server returns 402 Payment Required, the hashcash flow will be triggered.")

	// Set a breakpoint here in GoLand to start debugging
	fmt.Println("DEBUG: Starting API tests - set breakpoint here")

	// Test 1: Login
	fmt.Println("\n=== Test 1: Login ===")
	start := time.Now()

	// Set another breakpoint here to debug the login process
	fmt.Println("DEBUG: About to call Login - set breakpoint here")
	err := m.Login(email, password)
	if err != nil {
		log.Fatalf("Login failed: %v", err)
	}
	fmt.Printf("Login successful in %v\n", time.Since(start))

	// Test 2: Get user info
	fmt.Println("\n=== Test 2: Get User Info ===")
	start = time.Now()

	// Set breakpoint here to debug user info retrieval
	fmt.Println("DEBUG: About to call GetUser - set breakpoint here")
	user, err := m.GetUser()
	if err != nil {
		log.Printf("GetUser failed: %v", err)
	} else {
		fmt.Printf("User info retrieved in %v: Email=%s\n", time.Since(start), user.Email)
	}

	// Test 3: Get quota info
	fmt.Println("\n=== Test 3: Get Quota Info ===")
	start = time.Now()

	// Set breakpoint here to debug quota info retrieval
	fmt.Println("DEBUG: About to call GetQuota - set breakpoint here")
	quota, err := m.GetQuota()
	if err != nil {
		log.Printf("GetQuota failed: %v", err)
	} else {
		fmt.Printf("Quota info retrieved in %v: Used=%d, Total=%d\n",
			time.Since(start), quota.Cstrg, quota.Mstrg)
	}

	// Test 4: List root directory
	fmt.Println("\n=== Test 4: List Root Directory ===")
	start = time.Now()
	root := m.FS.GetRoot()
	if root != nil {
		children, err := m.FS.GetChildren(root)
		if err != nil {
			log.Printf("GetChildren failed: %v", err)
		} else {
			fmt.Printf("Root directory listed in %v: %d items found\n",
				time.Since(start), len(children))
			for i, child := range children {
				if i < 20 { // Show first 5 items
					fmt.Printf("  - %s (type: %d, size: %d)\n",
						child.GetName(), child.GetType(), child.GetSize())
				}
			}
			if len(children) > 20 {
				fmt.Printf("  ... and %d more items\n", len(children)-5)
			}
		}
	}

	fmt.Println("\n=== All tests completed ===")
	fmt.Println("If you saw any [DEBUG] messages mentioning 'hashcash', the feature was triggered!")
}

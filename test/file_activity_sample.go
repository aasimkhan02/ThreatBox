package main

import (
	"fmt"
	"os"
)

func main() {
	path := `C:\ThreatBox\output\threatbox_test.txt`
	renamed := `C:\ThreatBox\output\threatbox_test_renamed.txt`

	fmt.Println("Creating file...")
	if err := os.WriteFile(path, []byte("ThreatBox file activity test"), 0644); err != nil {
		panic(err)
	}

	fmt.Println("Reading file...")
	data, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(data))

	fmt.Println("Appending to file...")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
	}
	_, err = f.WriteString("\nMore data")
	f.Close()
	if err != nil {
		panic(err)
	}

	fmt.Println("Renaming file...")
	if err := os.Rename(path, renamed); err != nil {
		panic(err)
	}

	fmt.Println("Deleting file...")
	if err := os.Remove(renamed); err != nil {
		panic(err)
	}

	fmt.Println("File activity test completed")
}
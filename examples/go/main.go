package main

import (
	"fmt"
	"time"
)

func main() {
	for {
		time.Sleep(2 * time.Second)

		fmt.Println(time.Now())
	}
}

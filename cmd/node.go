package main

import (
	"fabricfork/internal/peer/common"
	"fmt"
)

func main() {
	err := common.LoadConfig()
	if err != nil {
		panic(err)
	}

	err = common.InitCmd()
	if err != nil {
		panic(err)
	}

	fmt.Println("msp ok")
}

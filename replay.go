package main

import (
	"fmt"
	"io/ioutil"
	"strings"
	"os"

	"github.com/johnso51/http2fuzz/util"
	"github.com/johnso51/http2fuzz/fuzzer"
)

func main() {
	filename := ""
	hostname := ""
	if len(os.Args) > 2 {
		filename = os.Args[1]
		hostname = os.Args[2]
	} else {
		fmt.Println("Usage: replay [JSON file] [host:port]\nExiting...")
		os.Exit(1)
	}
	file, err := ioutil.ReadFile(filename)
	if err != nil {
		panic(err)
	}

	var lines []string
	lines = strings.Split(string(file),"\n")

	for _, frameJSON := range lines {
		if len(frameJSON) < 1 {
			break
		}
		frame := util.FromJSON([]byte(frameJSON))
		c := fuzzer.NewConnection("192.168.0.41:443", true, true, true)

		switch frame["FrameMethod"] {
		case "RawFrame":
			fmt.Println(frame)
			frameType := uint8(frame["FrameType"].(float64))
			flags := uint8(frame["Flags"].(float64))
			streamID := uint32(frame["StreamID"].(float64))
			payload := util.FromBase64(frame["Payload"].(string))
			c.WriteRawFrame(frameType, flags, streamID, payload)
		case "PingFrame":
			fmt.Println(frame)
			data := [8]byte{byte(frame["Byte1"].(float64)),byte(frame["Byte2"].(float64)),byte(frame["Byte3"].(float64)),byte(frame["Byte4"].(float64)),byte(frame["Byte5"].(float64)),byte(frame["Byte6"].(float64)),byte(frame["Byte7"].(float64)),byte(frame["Byte8"].(float64))}
			fmt.Println("SENDING DATA ", data)
			c.SendPing(data)
		}
	}
}

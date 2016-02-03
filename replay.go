package main

import (
	"fmt"
	"io/ioutil"
	"strings"
	"os"
	"io"

	"github.com/johnso51/http2fuzz/util"
	"github.com/johnso51/http2fuzz/fuzzer"
	"github.com/bradfitz/http2"
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
		c := fuzzer.NewConnection(hostname, true, true, true)

		switch frame["FrameMethod"] {
		case "RawFrame":
			fmt.Println(frame)
			frameType := http2.FrameType(uint8(frame["FrameType"].(float64)))
			flags := http2.Flags(uint8(frame["Flags"].(float64)))
			streamID := uint32(frame["StreamID"].(float64))
			payload := util.FromBase64(frame["Payload"].(string))
			c.Framer.WriteRawFrame(frameType, flags, streamID, payload)
		case "PingFrame":
			fmt.Println(frame)
			data := [8]byte{byte(frame["Byte1"].(float64)),byte(frame["Byte2"].(float64)),byte(frame["Byte3"].(float64)),byte(frame["Byte4"].(float64)),byte(frame["Byte5"].(float64)),byte(frame["Byte6"].(float64)),byte(frame["Byte7"].(float64)),byte(frame["Byte8"].(float64))}
			fmt.Println("SENDING DATA ", data)
			c.Framer.WritePing(false,data)
		case "SettingsFrame":
			fmt.Println(frame)
			num_settings := uint32(frame["NumberSettings"].(float64))
			settings := []http2.Setting{}
			for s := uint32(1); s < num_settings; s++ {
				setting_id := fmt.Sprintf("SettingID_%d", s)
				setting_val := fmt.Sprintf("SettingVal_%d", s)
				setting := http2.Setting{
					ID:		http2.SettingID(frame[setting_id].(float64)),
					Val:	uint32(frame[setting_val].(float64)),
				}
				settings = append(settings, setting)
			}
			fmt.Println("Settings: ", settings)
			c.Framer.WriteSettings(settings...)
		case "PushPromise":
			fmt.Println(frame)
			promise := http2.PushPromiseParam{
				StreamID:		uint32(frame["StreamID"].(float64)),
				PromiseID:		uint32(frame["PromiseID"].(float64)),
				BlockFragment:	util.FromBase64(frame["BlockFragment"].(string)),
				EndHeaders:		bool(frame["EndHeaders"].(bool)),
				PadLength:		uint8(frame["PadLength"].(float64)),
			}
			fmt.Println("Push Promise: ", promise)
			c.Framer.WritePushPromise(promise)
		case "HeaderFrame":
			header_frame := http2.HeadersFrameParam{
				StreamID:		uint32(frame["StreamID"].(float64)),
				BlockFragment:	util.FromBase64(frame["BlockFragment"].(string)),
				EndStream:		bool(frame["EndStream"].(bool)),
				EndHeaders:		bool(frame["EndHeaders"].(bool)),
			}
			fmt.Println("Headers: ", header_frame)
			c.Framer.WriteHeaders(header_frame)
		case "RawTCPFrame":
			payload := frame["Payload"].(string)
			fmt.Println("RawTCP: ", payload)
			io.WriteString(c.Raw, string(payload))
		case "PriorityFrame":
			priority := http2.PriorityParam{
				StreamDep:	uint32(frame["StreamDep"].(float64)),
				Exclusive:	bool(frame["Exclusive"].(bool)),
				Weight:		uint8(frame["Weight"].(float64)),
			}
			streamID := uint32(frame["StreamID"].(float64))
			fmt.Println("PriorityFrame")
			c.Framer.WritePriority(streamID, priority)
		case "ContinuationFrame":
			streamID := uint32(frame["StreamID"].(float64))
			endStream := bool(frame["EndStream"].(bool))
			payload := util.FromBase64(frame["Payload"].(string))
			c.Framer.WriteContinuation(streamID, endStream, payload)
		case "DataFrame":
			streamID := uint32(frame["StreamID"].(float64))
			endStream := bool(frame["EndStream"].(bool))
			payload := util.FromBase64(frame["Payload"].(string))
			c.Framer.WriteData(streamID, endStream, payload)
		case "WindowUpdate":
			streamID := uint32(frame["StreamID"].(float64))
			incr := uint32(frame["Increment"].(float64))
			c.Framer.WriteWindowUpdate(streamID, incr)
		case "ResetFrame":
			streamID := uint32(frame["StreamID"].(float64))
			errorCode := http2.ErrCode(frame["ErrorCode"].(float64))
			c.Framer.WriteRSTStream(streamID, errorCode)
		}
	}
}

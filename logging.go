package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"
)

// Gelf represents one GELF message
type Gelf struct {
	Version      string `json:"version"`
	Host         string `json:"host"`
	SrcIP        string `json:"_srcip"`
	SrcPort      string `json:"_srcport"`
	ShortMessage string `json:"short_message"`
	FullMessage  string `json:"full_message"`
	TimeStamp    int64  `json:"timestamp"`
	Level        int    `json:"level"`
}

func sendGELF(item Gelf, client *http.Client) {
	buf, err := json.Marshal(item)
	if err != nil {
		fmt.Printf("%s: %s\n", time.Now().Format(time.RFC3339), err)
		return
	}

	reader := bytes.NewReader(buf)

	resp, err := client.Post(config.Logging.GraylogURL, "text/plain", reader)
	if err != nil {
		fmt.Printf("%s: %s\n", time.Now().Format(time.RFC3339), err)
		return
	}
	defer resp.Body.Close()
}

// LogAlerts logs alerts
func LogAlerts(pr ParseResults, a Alerts, client *http.Client) {
	for k := range a.Messages {
		if config.Logging.Console {
			fmt.Printf("%s: [%s:%s] %s\n", pr.TimeStamp.Format(time.RFC3339), pr.SrcIP, pr.SrcPort, a.Messages[k])
		}
		if config.Logging.Graylog {
			message := Gelf{}
			message.Version = "1.1"
			message.Host, _ = os.Hostname()
			message.SrcIP = pr.SrcIP.String()
			message.SrcPort = pr.SrcPort.String()
			message.ShortMessage = a.Messages[k]
			message.FullMessage = a.Messages[k]
			message.TimeStamp = pr.TimeStamp.Unix()
			message.Level = 4
			sendGELF(message, client)
		}
	}
}

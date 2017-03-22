package main

import (
	"crypto/rand"
	"crypto/tls"
	"log"
	"time"
)

func main() {
	conf := &tls.Config{
		InsecureSkipVerify: true,
	}

	conn, err := tls.Dial("tcp", "192.122.190.105:443", conf)
	if err != nil {
		log.Println(err)
		return
	}
	defer conn.Close()

	n, err := conn.Write([]byte("POST / HTTP/1.1\r\nHost: example.com\r\nX-Ignore: IamTapDanceIncompleteHTTPRequest\r\nContent-Type: multipart/form-data; boundary=----WebKitFormBoundaryePkpFF7tjBAqx29L\r\nContent-Length: 99999999\r\n\r\n----WebKitFormBoundaryePkpFF7tjBAqx29L\r\nContent-Disposition: form-data; name=\"td\"\r\n\r\n"))
	if err != nil {
		log.Println(n, err)
		return
	}

	// See if we got any data
	timeout := make(chan bool, 1)
	go func() {
		time.Sleep(1 * time.Second)
		timeout <- true
	}()
	data := make(chan []byte, 1)
	go func() {
		x := make([]byte, 1024)
		conn.Read(x)
		data <- x
	}()
	select {
	case <-timeout:
		log.Println("timed out, nothing to see")
		break
	case c := <-data:
		log.Println("got data: ", c)
		break
	}

	for j := 0; j < 1024; j++ {
		b := make([]byte, 1024)
		_, err := rand.Read(b)
		if err != nil {
			log.Println("error:", err)
			return
		}
		conn.Write(b)
	}
	log.Println("Wrote 1MB!")

	r := make([]byte, 1024)
	_, err = conn.Read(r)
	if err != nil {
		log.Println("error conn.Read:", err)
		return
	}
	log.Println("Hmmm, got: ", r)

}

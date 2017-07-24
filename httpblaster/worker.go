/*
Copyright 2016 Iguazio.io Systems Ltd.

Licensed under the Apache License, Version 2.0 (the "License") with
an addition restriction as set forth herein. You may not use this
file except in compliance with the License. You may obtain a copy of
the License at http://www.apache.org/licenses/LICENSE-2.0.

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
implied. See the License for the specific language governing
permissions and limitations under the License.

In addition, you may not use the software for any purposes that are
illegal under applicable law, and the grant of the foregoing license
under the Apache 2.0 license is conditioned upon your compliance with
such restriction.
*/
package httpblaster

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/valyala/fasthttp"
	"log"
	"net"
	"sync"
	"time"
	"encoding/pem"
	"crypto/x509"
)

const DialTimeout = 60 * time.Second

type worker_results struct {
	count uint64
	min   time.Duration
	max   time.Duration
	avg   time.Duration
	read  uint64
	write uint64
	codes map[int]uint64
}

type worker struct {
	host                string
	conn                net.Conn
	results             worker_results
	connection_restarts uint32
	error_count         uint32
	is_tls_client       bool
	br                  *bufio.Reader
	bw                  *bufio.Writer
	ch_duration         chan time.Duration
	ch_error            chan error
	lazy_sleep          time.Duration
}

func (w *worker) send_request(req *fasthttp.Request) (error, time.Duration) {
	response := fasthttp.AcquireResponse()
	response.Reset()
	defer fasthttp.ReleaseResponse(response)

	var (
		code int
	)
	if w.lazy_sleep > 0 {
		time.Sleep(w.lazy_sleep)
	}
	err, duration := w.send(req, response, time.Second*60)

	if err == nil {
		code = response.StatusCode()
		w.results.codes[code]++

		w.results.count++
		if duration < w.results.min {
			w.results.min = duration
		}
		if duration > w.results.max {
			w.results.max = duration
		}
		w.results.avg = w.results.avg + (duration-w.results.avg)/time.Duration(w.results.count)
	} else {
		w.error_count++
		log.Println("[ERROR]", err.Error())

	}
	if response.ConnectionClose() {
		w.restart_connection()
	}
	return err, duration
}

func (w *worker) open_connection() {
	if w.is_tls_client {
		w.open_secure_connection()
		return
	}
	conn, err := fasthttp.DialTimeout(w.host, DialTimeout)
	//conn.SetReadDeadline(time.Now().Add(time.Second*30))
	//conn.SetWriteDeadline(time.Now().Add(time.Second*30))
	if err != nil {
		panic(err)
		log.Printf("open connection error: %s\n", err)
	}
	if w.is_tls_client {
		conf := &tls.Config{
			InsecureSkipVerify: true,
		}
		w.conn = tls.Client(conn, conf)
	} else {
		w.conn = conn
	}
	w.br = bufio.NewReaderSize(w.conn, 1024*1024)
	w.bw = bufio.NewWriter(w.conn)
}


func (w *worker) open_secure_connection(){
	client_cert := `-----BEGIN CERTIFICATE-----
MIIC6DCCAdCgAwIBAgIIG/ia1DcCQ2UwDQYJKoZIhvcNAQELBQAwNDELMAkGA1UE
BhMCVVMxEDAOBgNVBAcTB1NlYXR0bGUxEzARBgNVBAMTCkFwaUdhdGV3YXkwHhcN
MTcwNzIzMDkwOTA4WhcNMTgwNzIzMDkwOTA4WjA0MQswCQYDVQQGEwJVUzEQMA4G
A1UEBxMHU2VhdHRsZTETMBEGA1UEAxMKQXBpR2F0ZXdheTCCASIwDQYJKoZIhvcN
AQEBBQADggEPADCCAQoCggEBANC/PmqZEwyX9pmEEXYabfjxQ2/3p2WGFvwyZRtV
eaH3FpuJhTjwm0/niMdopgVDhl8Z9ZmEYMzUbuKO4oITEVzlyvzPoZoihcmGF7k1
MWsDX7jvJdjR9fGPasLOFEJJ/PxP+Cb9DsP2JZsS+dEEzrS/qr0l1rEnIvuHnCrQ
3qlSgUaT0JWF/F8EFPGXxbleL0i+Z4s/GBNxvDwReihJUz96w8vg3aRpVIJHo9nL
v1Oj7t6R14vB8Wb5zeXFKfER+0JS3YPpUQxrqt69Xxl+obHCddY3mO3aanNTuMfw
zF9srXnkzQW7jICi+z0HGevIlHvfcq5j8yJMT10Cz5S9dmUCAwEAATANBgkqhkiG
9w0BAQsFAAOCAQEAJ8q8g7nAfJFwvTDGRq7GUQNE6xUrBcVOdhfpUZgkrtZYZbWt
Y9rURGxMhMJYgfdcUL3hXa/yNiSU8H+wGOL0UTSVIkA/NxsVw/bDic5MVXi9ttZ/
Q3LQI9GS1BqLxSJ86odNprJSYdjLCYq+h3ghQHuElDLf7/LFCtVYgWfNCMLJ9AX+
dN5bsHRPreqTeozPOIio6zhQGSor67Z7NqlZF1EoJBcK73AobfeAsK+ib1FLRZY1
v0qPpbfPWUt+QQ5ITdRFbUrRJIm4lxzcy0A/RMT8jXI3yPU+K/YSzMgOHDU8MChN
7eTcZwceFs3kS8iwRj/O01vPTBv76yIYlmlrxQ==
-----END CERTIFICATE-----`
	conn, err := fasthttp.DialTimeout(w.host, DialTimeout)
	block ,_ := pem.Decode([]byte (client_cert))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic(err)
		log.Fatal(err)
	}
	clientCertPool := x509.NewCertPool()
	clientCertPool.AddCert(cert)

	if w.is_tls_client {
		conf := &tls.Config{
			ServerName:"29mbw8bh6b.execute-api.us-east-1.amazonaws.com",
			ClientAuth: tls.RequireAndVerifyClientCert,
			InsecureSkipVerify: true,
			ClientCAs: clientCertPool,
		}
		c := tls.Client(conn, conf)
		err:= c.Handshake()
		if err != nil{
			panic(err)
		}
		w.conn = c
	} else {
		w.conn = conn
	}
	w.br = bufio.NewReaderSize(w.conn, 1024*1024)
	w.bw = bufio.NewWriter(w.conn)
}



func (w *worker) close_connection() {
	if w.conn != nil {
		w.conn.Close()
	}
}

func (w *worker) restart_connection() {
	w.close_connection()
	w.open_connection()
	w.connection_restarts++
}

func (w *worker) send(req *fasthttp.Request, resp *fasthttp.Response,
	timeout time.Duration) (error, time.Duration) {
	var err error
	go func() {
		start := time.Now()
		if err = req.Write(w.bw); err != nil {
			log.Printf("send write error: %s\n", err)
			log.Println(fmt.Sprintf("%+v", req))
			w.ch_error <- err
		} else if err = w.bw.Flush(); err != nil {
			log.Printf("send flush error: %s\n", err)
			w.ch_error <- err
		} else if err = resp.Read(w.br); err != nil {
			log.Printf("send read error: %s\n", err)
			w.ch_error <- err
		}
		end := time.Now()
		w.ch_duration <- end.Sub(start)
	}()
	select {
	case duration := <-w.ch_duration:
		log.Println(fmt.Sprintf("%+v", resp))
		return nil, duration
	case err := <-w.ch_error:
		log.Printf("rerquest completed with error:%s", err.Error())
		return err, timeout
	case <-time.After(timeout):
		log.Printf("Error: request didn't complete on timeout url:%s", req.URI().String())
		return errors.New(fmt.Sprintf("request timedout url:%s", req.URI().String())), timeout
	}
	return nil, timeout
}

func (w *worker) run_worker(ch_req chan *fasthttp.Request, wg *sync.WaitGroup, release_req bool) {
	defer wg.Done()
	for req := range ch_req {
		w.send_request(req)
		if release_req {
			fasthttp.ReleaseRequest(req)
		}
	}
}

func NewWorker(host string, tls_client bool, lazy int) *worker {
	if host == "" {
		return nil
	}
	worker := worker{host: host, is_tls_client: tls_client}
	worker.results.codes = make(map[int]uint64)
	worker.open_connection()
	worker.ch_duration = make(chan time.Duration, 1)
	worker.ch_error = make(chan error, 1)
	worker.lazy_sleep = time.Duration(lazy) * time.Millisecond
	return &worker
}

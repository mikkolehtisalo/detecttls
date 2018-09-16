package main

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// WGPool is used for implementing graceful exit
var WGPool sync.WaitGroup

// Job represents the job to be run
type Job struct {
	Packet gopacket.Packet
}

// InitializeJobQueue sets the queue up
func InitializeJobQueue(maxqueue int, maxworkers int) {
	JobQueue = make(chan Job, maxqueue)
	dispatcher := NewDispatcher(maxworkers)
	dispatcher.Run()
}

// JobQueue is a buffered channel that we can send work requests on
var JobQueue chan Job

// Worker represents the worker that executes the job
type Worker struct {
	WorkerPool chan chan Job
	JobChannel chan Job
	quit       chan bool
	eth        *layers.Ethernet
	ip4        *layers.IPv4
	ip6        *layers.IPv6
	tcp        *layers.TCP
	parser     *gopacket.DecodingLayerParser
	decoded    *[]gopacket.LayerType
	httpClient *http.Client
}

// NewWorker initializes a new worker
func NewWorker(workerPool chan chan Job) Worker {
	w := Worker{}
	w.WorkerPool = workerPool
	w.JobChannel = make(chan Job)
	w.quit = make(chan bool)
	w.eth = &layers.Ethernet{}
	w.ip4 = &layers.IPv4{}
	w.ip6 = &layers.IPv6{}
	w.tcp = &layers.TCP{}
	w.parser = gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, w.eth, w.ip4, w.ip6, w.tcp)
	w.parser.DecodingLayerParserOptions.IgnoreUnsupported = true
	w.decoded = &[]gopacket.LayerType{}
	w.httpClient = buildHTTPClient()
	return w
}

func buildHTTPClient() *http.Client {
	if config.Logging.useTLS {
		return buildTLSClient()
	}
	// Else build non-TLS client
	return &http.Client{}
}

func buildTLSClient() *http.Client {
	var tlsConfig *tls.Config
	if config.Logging.GraylogAllowInsecure {
		tlsConfig = &tls.Config{RootCAs: x509.NewCertPool(), InsecureSkipVerify: true}
	} else {
		tlsConfig = &tls.Config{RootCAs: x509.NewCertPool()}
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	client := &http.Client{Transport: transport}
	ok := tlsConfig.RootCAs.AppendCertsFromPEM(config.Logging.pemData)
	if !ok {
		panic("Unable to load CA data")
	}
	return client
}

// Start method starts the run loop for the worker, listening for a quit channel in
// case we need to stop it
func (w *Worker) Start() {
	go func() {
		for {
			// register the current worker into the worker queue.
			w.WorkerPool <- w.JobChannel

			select {
			case job := <-w.JobChannel:
				presults := ParsePacket(w, &job)
				if presults.HasTLSRecords {
					alerts := getAlertsFromParseResults(presults)
					if len(alerts.Messages) != 0 {
						LogAlerts(presults, alerts, w.httpClient)
					}
				}
				WGPool.Done()
			case <-w.quit:
				// we have received a signal to stop
				return
			}
		}
	}()
}

// Stop signals the worker to stop listening for work requests.
func (w Worker) Stop() {
	go func() {
		w.quit <- true
	}()
}

// Dispatcher handles finding workers for the jobs
type Dispatcher struct {
	// A pool of workers channels that are registered with the dispatcher
	WorkerPool chan chan Job
	maxWorkers int
}

// NewDispatcher creates a new Dispatcher
func NewDispatcher(maxWorkers int) *Dispatcher {
	pool := make(chan chan Job, maxWorkers)
	return &Dispatcher{WorkerPool: pool, maxWorkers: maxWorkers}
}

// Run starts the workers and dispatcher
func (d *Dispatcher) Run() {
	// starting n number of workers
	for i := 0; i < d.maxWorkers; i++ {
		worker := NewWorker(d.WorkerPool)
		worker.Start()
	}

	go d.dispatch()
}

func (d *Dispatcher) dispatch() {
	for {
		select {
		case job := <-JobQueue:
			// a job request has been received
			go func(job Job) {
				// try to obtain a worker job channel that is available.
				// this will block until a worker is idle
				jobChannel := <-d.WorkerPool

				// dispatch the job to the worker job channel
				jobChannel <- job
			}(job)
		}
	}
}

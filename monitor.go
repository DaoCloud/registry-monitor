package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/coreos/pkg/flagutil"
	"github.com/fsouza/go-dockerclient"
	"github.com/prometheus/client_golang/prometheus"

	log "github.com/Sirupsen/logrus"
	"encoding/json"
	"bytes"
	"errors"
)

var listen = flag.String("listen", ":8000", "")
var level = flag.String("loglevel", "info", "default log level: debug, info, warn, error, fatal, panic")
var dockerUsername = flag.String("username", "", "Registry username for pulling and pushing")
var dockerPassword = flag.String("password", "", "Registry password for pulling and pushing")
var registryHost = flag.String("registry-host", "", "Hostname of the registry being monitored")
var repository = flag.String("repository", "", "Repository on the registry to pull and push")
var baseLayer = flag.String("base-layer-id", "", "Docker V1 ID of the base layer in the repository")
var pagedutyServiceKey = flag.String("pageduty-service-key", "", "pageduty service key")
var monitorLocation = flag.String("monitor-location", "", "monitor location")
var checkJobDuration = flag.Int("checkjob-duration", 2, "checkJob duration")

const DefaultPagerDutyAPIURL = "https://events.pagerduty.com/generic/2010-04-15/create_event.json"

var (
	healthy bool
	status bool
	status_detail string
)

var (
	promNamespace = os.Getenv("PROMETHEUS_NAMESPACE")

	promSuccessMetric = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: promNamespace,
		Subsystem: "",
		Name:      "monitor_success",
		Help:      "The registry monitor successfully completed a pull and push operation",
	}, []string{})

	promFailureMetric = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: promNamespace,
		Subsystem: "",
		Name:      "monitor_failure",
		Help:      "The registry monitor failed to complete a pull and push operation",
	}, []string{})

	promPushMetric = prometheus.NewSummary(prometheus.SummaryOpts{
		Namespace: promNamespace,
		Subsystem: "",
		Name:      "monitor_push",
		Help:      "The time for the monitor push operation",
	})

	promPullMetric = prometheus.NewSummary(prometheus.SummaryOpts{
		Namespace: promNamespace,
		Subsystem: "",
		Name:      "monitor_pull",
		Help:      "The time for the monitor pull operation",
	})
)

var prometheusMetrics = []prometheus.Collector{promSuccessMetric, promFailureMetric, promPullMetric, promPushMetric}

type LoggingWriter struct{}

func (w *LoggingWriter) Write(p []byte) (n int, err error) {
	s := string(p)
	log.Infof("%s", s)
	return len(s), nil
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	if !healthy {
		w.WriteHeader(503)
	}

	fmt.Fprintf(w, "%t", healthy)
}

func statusHandler(w http.ResponseWriter, r *http.Request) {
	if !status {
		w.WriteHeader(400)
	}
	fmt.Fprintf(w, "%t", status)
}

func alert() {
	duration := time.Duration(*checkJobDuration) * time.Minute
	for{
		log.Infof("Sleeping for %v", duration)
		time.Sleep(duration)
		if err := pageduty(status,healthy,status_detail); err != nil {
			log.Errorf("failed to alert PagerDuty . err: %v", err)
		}

	}

}

func pageduty(status,healthy bool,status_detail string) error {
	if *pagedutyServiceKey == "" {
		log.Info("pagedutyServiceKey not define, do nothing.")
		return nil
	}
	if *monitorLocation == "" {
		resp, err := http.Get("http://ifconfig.me/ip")
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		monitorLocationStr := string(body)
		monitorLocation = &monitorLocationStr
	}
	var eventType string
	if status == false ||healthy ==false{
		eventType = "trigger"
	} else {
		eventType = "resolve"
	}
	pagedutyData := make(map[string]string)
	pagedutyData["service_key"] = *pagedutyServiceKey
	pagedutyData["event_type"] = eventType
	pagedutyData["description"] = fmt.Sprintf("registry[%v][location:%v] pull or push  healthy: %v, status: %v . ", *registryHost, *monitorLocation,healthy, status)
	pagedutyData["incident_key"] = *monitorLocation
	pagedutyData["client"] = "registry_monitor"
	pagedutyData["client_url"] = *monitorLocation
	pagedutyData["details"] = fmt.Sprintf("registry[%v][location:%v] pull or push  healthy: %v, status: %v , status_detail : %v ", *registryHost, *monitorLocation,healthy, status,status_detail)

	// Post data to PagerDuty
	var post bytes.Buffer
	enc := json.NewEncoder(&post)
	err := enc.Encode(pagedutyData)
	if err != nil {
		return err
	}
	resp, err := http.Post(DefaultPagerDutyAPIURL, "application/json", &post)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		errMessage := fmt.Sprintf("failed to understand PagerDuty response. code: %d content: %s", resp.StatusCode, string(body))
		return errors.New(errMessage)
	}
	if status == false ||healthy ==false{
		log.Info("pageduty alert send")
	}
	return nil
}

func buildTLSTransport(basePath string) (*http.Transport, error) {
	roots := x509.NewCertPool()
	pemData, err := ioutil.ReadFile(filepath.Join(basePath, "ca.pem"))
	if err != nil {
		return nil, err
	}

	// Add the certification to the pool.
	roots.AppendCertsFromPEM(pemData)

	// Create the certificate.
	crt, err := tls.LoadX509KeyPair(filepath.Join(basePath, "/cert.pem"), filepath.Join(basePath, "/key.pem"))
	if err != nil {
		return nil, err
	}

	// Create the new tls configuration using both the authority and certificate.
	conf := &tls.Config{
		RootCAs:      roots,
		Certificates: []tls.Certificate{crt},
	}

	// Create our own transport and return it.
	return &http.Transport{
		TLSClientConfig: conf,
	}, nil
}

func newDockerClient(dockerHost string) (*docker.Client, error) {
	if os.Getenv("DOCKER_CERT_PATH") == "" {
		return docker.NewClient(dockerHost)
	}

	cert_path := os.Getenv("DOCKER_CERT_PATH")
	ca := fmt.Sprintf("%s/ca.pem", cert_path)
	cert := fmt.Sprintf("%s/cert.pem", cert_path)
	key := fmt.Sprintf("%s/key.pem", cert_path)
	return docker.NewTLSClient(dockerHost, cert, key, ca)
}

func stringInSlice(value string, list []string) bool {
	for _, current := range list {
		if current == value {
			return true
		}
	}
	return false
}

func verifyDockerClient(dockerClient *docker.Client) bool {
	log.Infof("Trying to connect to Docker client")
	if err := dockerClient.Ping(); err != nil {
		status_detail=fmt.Sprintf("Error connecting to Docker client: %s", err)
		log.Errorf("%s",status_detail)
		healthy = false
		return false
	}

	log.Infof("Docker client valid")
	return true
}

func clearAllContainers(dockerClient *docker.Client) bool {
	listOptions := docker.ListContainersOptions{
		All: true,
	}

	log.Infof("Listing all containers")
	containers, err := dockerClient.ListContainers(listOptions)
	if err != nil {
		status_detail=fmt.Sprintf("Error listing containers: %s", err)
		log.Errorf("%s",status_detail)
		healthy = false
		return false
	}

	for _, container := range containers {
		if stringInSlice("monitor", container.Names) {
			continue
		}

		log.Infof("Removing container: %s", container.ID)
		removeOptions := docker.RemoveContainerOptions{
			ID:            container.ID,
			RemoveVolumes: true,
			Force:         true,
		}

		if err = dockerClient.RemoveContainer(removeOptions); err != nil {
			status_detail=fmt.Sprintf("Error removing container: %s", err)
			log.Errorf("%s",status_detail)
			healthy = false
			return false
		}
	}

	return healthy
}

func clearAllImages(dockerClient *docker.Client) bool {
	// Note: We delete in a loop like this because deleting one
	// image can lead to others being deleted. Therefore, we just
	// loop until the images list are empty.

	skipImages := map[string]bool{}

	for {
		// List all Docker images.
		listOptions := docker.ListImagesOptions{
			All: true,
		}

		log.Infof("Listing docker images")
		images, err := dockerClient.ListImages(listOptions)
		if err != nil {
			status_detail=fmt.Sprintf("Could not list images: %s", err)
			log.Errorf("%s",status_detail)
			healthy = false
			return false
		}

		// Determine if we need to remove any images.
		imagesFound := false
		for _, image := range images {
			if _, toSkip := skipImages[image.ID]; toSkip {
				continue
			}

			imagesFound = true
		}

		if !imagesFound {
			return healthy
		}

		// Remove images.
		removedImages := false
		for _, image := range images[:1] {
			if _, toSkip := skipImages[image.ID]; toSkip {
				continue
			}

			log.Infof("Clearing image %s", image.ID)
			if err = dockerClient.RemoveImage(image.ID); err != nil {
				if strings.ToLower(os.Getenv("UNDER_DOCKER")) != "true" {
					status_detail=fmt.Sprintf("RemoveImage err: %s", err)
					log.Errorf("%s",status_detail)
					healthy = false
					return false
				} else {
					log.Warningf("Skipping deleting image %v", image.ID)
					skipImages[image.ID] = true
					continue
				}
			}

			removedImages = true
		}

		if !removedImages {
			break
		}
	}

	return true
}

func pullTestImage(dockerClient *docker.Client) bool {
	pullOptions := docker.PullImageOptions{
		Repository:   *repository,
		Registry:     "quay.io",
		Tag:          "latest",
		OutputStream: &LoggingWriter{},
	}

	pullAuth := docker.AuthConfiguration{
		Username: *dockerUsername,
		Password: *dockerPassword,
	}

	if err := dockerClient.PullImage(pullOptions, pullAuth); err != nil {
		log.Errorf("Pull Error: %s", err)
		status_detail=fmt.Sprintf("Pull Error err %s",err)
		status = false
		return false
	}

	return true
}

func deleteTopLayer(dockerClient *docker.Client) bool {
	imageHistory, err := dockerClient.ImageHistory(*repository)
	if err != nil {
		status_detail=fmt.Sprintf("ImageHistory err: %s", err)
		log.Errorf("%s",status_detail)
		healthy = false
		return false
	}

	for _, image := range imageHistory {
		if stringInSlice("latest", image.Tags) {
			log.Infof("Deleting image %s", image.ID)
			if err = dockerClient.RemoveImage(image.ID); err != nil {
				status_detail=fmt.Sprintf("RemoveImage err: %s", err)
				log.Errorf("%s",status_detail)
				healthy = false
				return false
			}
			break
		}
	}

	return healthy
}

func createTagLayer(dockerClient *docker.Client) bool {
	t := time.Now().Local()
	timestamp := t.Format("2006-01-02 15:04:05 -0700")

	config := &docker.Config{
		Image: *baseLayer,
		Cmd:   []string{"sh", "echo", "\"" + timestamp + "\" > foo"},
	}

	container_name := fmt.Sprintf("updatedcontainer%v", time.Now().Unix())
	log.Infof("Creating new image via container %v", container_name)

	options := docker.CreateContainerOptions{
		Name:   container_name,
		Config: config,
	}

	if _, err := dockerClient.CreateContainer(options); err != nil {
		status_detail=fmt.Sprintf("Error creating container: %s", err)
		log.Errorf("%s",status_detail)
		healthy = false
		return false
	}

	commitOptions := docker.CommitContainerOptions{
		Container:  container_name,
		Repository: *repository,
		Tag:        "latest",
		Message:    "Updated at " + timestamp,
	}

	if _, err := dockerClient.CommitContainer(commitOptions); err != nil {
		status_detail=fmt.Sprintf("Error committing Container: %s", err)
		log.Errorf("%s",status_detail)
		healthy = false
		return false
	}

	log.Infof("Removing container: %s", container_name)
	removeOptions := docker.RemoveContainerOptions{
		ID:            container_name,
		RemoveVolumes: true,
		Force:         true,
	}

	if err := dockerClient.RemoveContainer(removeOptions); err != nil {
		status_detail=fmt.Sprintf("Error removing container: %s", err)
		log.Errorf("%s",status_detail)
		healthy = false
		return false
	}

	return healthy
}

func pushTestImage(dockerClient *docker.Client) bool {
	pushOptions := docker.PushImageOptions{
		Name:         *repository,
		Registry:     *registryHost,
		Tag:          "latest",
		OutputStream: &LoggingWriter{},
	}

	pushAuth := docker.AuthConfiguration{
		Username: *dockerUsername,
		Password: *dockerPassword,
	}

	if err := dockerClient.PushImage(pushOptions, pushAuth); err != nil {
		log.Errorf("Push Error: %s", err)
		status_detail=fmt.Sprintf("Push Error err %s",err)
		status = false
		return false
	}

	status = true
	return true
}

func main() {
	// Parse the command line flags.
	if err := flag.CommandLine.Parse(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
	if err := flagutil.SetFlagsFromEnv(flag.CommandLine, "REGISTRY_MONITOR"); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	lvl, err := log.ParseLevel(*level)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	log.SetLevel(lvl)

	// Ensure we have proper values.
	if *dockerUsername == "" {
		log.Fatalln("Missing username flag")
	}

	if *dockerPassword == "" {
		log.Fatalln("Missing password flag")
	}

	if *registryHost == "" {
		log.Fatalln("Missing registry-host flag")
	}

	if *repository == "" {
		log.Fatalln("Missing repository flag")
	}

	if *baseLayer == "" {
		log.Fatalln("Missing base-layer-id flag")
	}

	// Register the metrics.
	for _, metric := range prometheusMetrics {
		err := prometheus.Register(metric)
		if err != nil {
			log.Fatalf("Failed to register metric: %v", err)
		}
	}

	// Setup the HTTP server.
	http.Handle("/metrics", prometheus.Handler())
	http.HandleFunc("/health", healthHandler)
	http.HandleFunc("/status", statusHandler)

	log.Infoln("Listening on", *listen)

	// Run the monitor routine.
	runMonitor()

	// Listen and serve.
	log.Fatal(http.ListenAndServe(*listen, nil))
}

func runMonitor() {
	dockerHost := os.Getenv("DOCKER_HOST")
	if dockerHost == "" {
		dockerHost = "unix:///var/run/docker.sock"
	}

	firstLoop := true
	healthy = true

	mainLoop := func() {
		duration := time.Duration(*checkJobDuration) * time.Minute

		for {
			if !firstLoop {
				log.Infof("Sleeping for %v", duration)
				time.Sleep(duration)
			}

			log.Infof("Starting test")
			firstLoop = false
			status = true

			log.Infof("Trying docker host: %s", dockerHost)
			dockerClient, err := newDockerClient(dockerHost)
			if err != nil {
				log.Errorf("%s", err)
				status_detail=fmt.Sprintf("newDockerClient err: %s",err)
				healthy = false
				return
			}

			if !verifyDockerClient(dockerClient) {
				return
			}

			if strings.ToLower(os.Getenv("UNDER_DOCKER")) != "true" {
				log.Infof("Clearing all containers")
				if !clearAllContainers(dockerClient) {
					return
				}
			}

			log.Infof("Clearing all images")
			if !clearAllImages(dockerClient) {
				return
			}

			log.Infof("Pulling test image")
			pullStartTime := time.Now()
			if !pullTestImage(dockerClient) {
				duration = time.Duration(*checkJobDuration * 30) * time.Second

				// Write the failure metric.
				m, err := promFailureMetric.GetMetricWithLabelValues()
				if err != nil {
					panic(err)
				}

				m.Inc()
				continue
			}

			// Write the pull time metric.
			promPullMetric.Observe(time.Since(pullStartTime).Seconds())

			log.Infof("Deleting top layer")
			if !deleteTopLayer(dockerClient) {
				return
			}

			log.Infof("Creating new top layer")
			if !createTagLayer(dockerClient) {
				return
			}

			log.Infof("Pushing test image")
			pushStartTime := time.Now()
			if !pushTestImage(dockerClient) {
				duration = time.Duration(*checkJobDuration * 30) * time.Second
				// Write the failure metric.
				m, err := promFailureMetric.GetMetricWithLabelValues()
				if err != nil {
					panic(err)
				}

				m.Inc()

				continue
			}

			// Write the push time metric.
			promPushMetric.Observe(time.Since(pushStartTime).Seconds())

			log.Infof("Test successful")
			duration = time.Duration(*checkJobDuration) * time.Minute

			// Write the success metric.
			m, err := promSuccessMetric.GetMetricWithLabelValues()
			if err != nil {
				panic(err)
			}

			m.Inc()

		}
	}

	go mainLoop()
	go alert()

}

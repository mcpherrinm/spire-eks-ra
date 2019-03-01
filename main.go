package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"

	"github.com/alecthomas/kong"
	"github.com/mcpherrinm/spire-eks-ra/grpcspiffe"
	"github.com/pkg/errors"
	"github.com/spiffe/spire/api/workload"
	"github.com/spiffe/spire/proto/api/registration"
	"github.com/spiffe/spire/proto/common"
	"google.golang.org/grpc"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

var Config struct {
	SpireServer   string `help:"Unix socket for Spire Server (empty to skip calling)" default:"unix:///tmp/spire-registration.sock"`
	SpireAuthed   bool   `help:"If true, use SPIFFE workload api to authenticate to SPIRE server"`
	KubeConfig    string `help:"Kubecfg file path; use InClusterConfig if not specified"`
	KubeMasterURL string `help:"Kubernetes master Url"`
	Region        string `help:"AWS Region" default:"us-east-2"`
	TrustDomain   string `required:"" help:"Spire trust domain"`
	AwsAccount    string `required:"" help:"AWS account agents are in"`
}

func main() {
	kong.Parse(&Config)

	var config *rest.Config
	var err error

	if Config.KubeConfig != "" {
		config, err = clientcmd.BuildConfigFromFlags(Config.KubeMasterURL, Config.KubeConfig)
	} else {
		config, err = rest.InClusterConfig()
	}
	if err != nil {
		log.Fatal(errors.Wrap(err, "loading kubernetes rest api config"))
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatal(err)
	}

	api := clientset.CoreV1()

	spiffeClient := workload.NewX509Client(&workload.X509ClientConfig{
		Addr: &net.UnixAddr{Net: "unix", Name: "/tmp/agent.sock"},
		Log:  logrus.StandardLogger(),
	})
	go func() {
		log.Print("Starting client")
		err = spiffeClient.Start()
		log.Print("Started client")
		if err != nil {
			log.Fatal(err)
		}
	}()

	var registrationClient registration.RegistrationClient
	if Config.SpireServer != "" {
		var authOption grpc.DialOption
		if Config.SpireAuthed {
			authOption = grpcspiffe.WithSpiffe(fmt.Sprintf("spiffe://%s/spire/server", Config.TrustDomain), spiffeClient)
		} else {
			authOption = grpc.WithInsecure()
		}
		spireConn, err := grpc.Dial(Config.SpireServer, authOption)
		if err != nil {
			log.Fatal(err)
		}
		registrationClient = registration.NewRegistrationClient(spireConn)
	}

	// hostMap maps Name to ProviderId
	// ie "ip-172-31-46-148.us-east-2.compute.internal" => "aws:///us-east-2a/i-0bc11c4b1c7a70acb"
	hostMap := &sync.Map{}

	// podMap maps a Pod UID to a registration ID
	podMap := &sync.Map{}

	nodesListOptions := meta.ListOptions{}

	hostWatch, err := api.Nodes().Watch(nodesListOptions)
	if err != nil {
		log.Fatal(err)
	}
	go func(c <-chan watch.Event) {
		for event := range c {
			host, ok := event.Object.(*core.Node)
			if !ok {
				log.Fatalf("Couldn't cast event: %q", event)
			}
			switch event.Type {
			case watch.Added:
				log.Printf("Added Name: %s, ProviderID: %s", host.Name, host.Spec.ProviderID)
				hostMap.Store(host.Name, host.Spec.ProviderID)
			case watch.Deleted:
				hostMap.Delete(host.Name)
			default:
				// TODO: Don't really care about modified etc, I think?
			}
		}
	}(hostWatch.ResultChan())

	nsListOptions := meta.ListOptions{}
	podListOptions := meta.ListOptions{}
	nsWatch, err := api.Namespaces().Watch(nsListOptions)
	if err != nil {
		log.Fatal(err)
	}

	for event := range nsWatch.ResultChan() {
		ns, ok := event.Object.(*core.Namespace)
		if !ok {
			// TODO: Expected in the error case?
			// Need to only check in Added/Deleted/Modified.
			// Put this cast inside those cases?
			log.Printf("Could not cast event.Object")
		}

		// Check if this namespace corresponds with an app we want to issue for
		// TODO: Sync from external list.
		// EG, kube-system does not need (and should not get) SPIFFE certs.
		if ns.Name == "kube-system" {
			continue
		}

		log.Printf("NS: %s %s", ns.Name, event.Type)
		switch event.Type {
		case watch.Added:
			// Add a watcher for all pods in this NS:
			podWatch, err := api.Pods(ns.Name).Watch(podListOptions)
			if err != nil {
				log.Fatal(err)
			}
			go func(ns string, ch <-chan watch.Event) {
				for event := range ch {
					pod, ok := event.Object.(*core.Pod)
					if !ok {
						log.Printf("Couldn't cast object %q %q", event.Object, event.Type)
					}
					switch event.Type {
					case watch.Added:
						log.Printf("Pod added: %s/%s to %q", ns, pod.Name, pod.Spec.NodeName)

						if providerIDi, ok := hostMap.Load(pod.Spec.NodeName); ok {
							// We need to turn a string like aws:///us-east-2a/i-0bc11c4b1c7a70acb into
							// a parent ID like this:
							// spiffe://spire-test.square/spire/agent/aws_iid/517588744928/us-east-2/i-054a742c454905005
							providerID, ok := providerIDi.(string)
							if !ok {
								panic(fmt.Sprintf("Invalid entry in hostMap: %q", providerIDi))
							}
							providerIDParts := strings.Split(providerID, "/")
							// "aws://az/instance" split = ["aws:", "", "", az, instanceID]
							if len(providerIDParts) != 5 {
								log.Panicf("Expected providerID to be of form aws:///az/id: %q (%d != 5)", providerIDParts, len(providerIDParts))
							}
							if providerIDParts[0] != "aws:" || providerIDParts[1] != "" || providerIDParts[2] != "" {
								log.Panicf("Expected providerID to start with aws:///")
							}

							az := providerIDParts[3]
							if !strings.HasPrefix(az, Config.Region) {
								log.Panicf("AZ not in this region? %s %s", az, Config.Region)
							}

							instanceID := providerIDParts[4]

							parentID := fmt.Sprintf("spiffe://%s/spire/agent/aws_iid/%s/%s/%s", Config.TrustDomain, Config.AwsAccount, Config.Region, instanceID)
							registrationEntry := common.RegistrationEntry{
								ParentId: parentID, // Wait, why isn't this a registration.ParentID?
								SpiffeId: fmt.Sprintf("spiffe://%s/%s", Config.TrustDomain, pod.Namespace),
								Selectors: []*common.Selector{
									{Type: "k8s", Value: fmt.Sprintf("pod-uid:%s", pod.UID)},
								},
							}
							log.Printf("Registration Entry: %s", registrationEntry.String())

							if Config.SpireServer != "" {
								entry, err := registrationClient.CreateEntry(context.Background(), &registrationEntry)
								if err != nil {
									log.Panicf("error registering: %v", err)
								}
								log.Printf("Registered, entryID: %s", entry.GetId())
								podMap.Store(pod.UID, entry.Id)
							} else {
								log.Printf("Skipping registration because no Spire Server is configured")
							}

						} else {
							// TODO: This could happen because we learned about the host after the pod
							// TODO: We can either look it up here or put it in a queue pending learning about the host.
							log.Printf("Host ProviderID not known, TODO handle this case.")
						}
					case watch.Deleted:
						if Config.SpireServer != "" {
							registrationEntryIDi, ok := podMap.Load(pod.UID)
							if !ok {
								log.Printf("Delete for a pod UID we haven't see? %s", pod.UID)
							}
							registrationEntryID, ok := registrationEntryIDi.(registration.RegistrationEntryID)

							if entry, err := registrationClient.DeleteEntry(context.TODO(), &registrationEntryID); err != nil {
								log.Printf("Error deleting entry: %v", err)
							} else {
								log.Printf("Deleted %v: %s/%s from %s", entry.SpiffeId, ns, pod.Name, pod.Spec.NodeName)
							}
						} else {
							log.Printf("Skipping delete because no Spire Server is configured")
						}
					case watch.Modified:
						// TODO: What do we do here?  Are there any changes that could affect issuance?
						log.Printf("Pod changed: %s/%s on %s", ns, pod.Name, pod.Spec.NodeName)
					case watch.Error:
					default:
						log.Printf("Something bad happened %q", event)
					}
				}
			}(ns.Name, podWatch.ResultChan())
		case watch.Deleted:
			log.Print("deleted")
			// Remove the watcher for this NS:
		case watch.Modified:
			log.Print("modified")
			// ???
		case watch.Error:
			log.Print("errored!")
			// ???
		default:
			log.Print("unhandled event type", event.Type)
		}
	}
}

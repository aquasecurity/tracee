package sigengine

import (
	"fmt"
	"os"
	"os/signal"
	"strings"
)

type SignaturesConfig struct {
	RequestedSigs []string // A list of the requested signatures by the user
	InputSources  []string // Available input sources (e.g. Tracee)
	Severity      string   // todo: change to enum
	PrintSigList  bool     // If chosen, print signatures list and exit
}

type Sigengine struct {
	config       SignaturesConfig
	InputSources map[string]InputSource    // Available input sources (e.g. Tracee)
	sigClasses   map[string]signatureClass // Supported languages and formats to write signatures
	sourceToReqs map[string][]sigReq       // Map from input source type to signatures requests
}

// sigReq represents one event request of a signature, assuming the input source is known
type sigReq struct {
	sigMeta  SigMetadata
	sigClass signatureClass
	evFilter EventFilter
}

type EventFilter struct {
	Name    string   // Name of the requested event
	Filters []Filter // Filters to be checked by the inputSource for the requested event
}

type SigMetadata struct {
	Name             string
	Description      string
	Authors          []string
	Tags             []string
	MitreCategory    []string
	MitreSubCategory []string
}

type signatureClass interface {
	getSigList() []SigMetadata
	getSigReqEvents(sigNames []string) (map[string][]RequestedEvent, error)
	initSigs(sigNames []string) error
	onEvent(sigName string, event Event) (SigResult, error)
	onComplete(sigNames []string) (map[string]SigResult, error)
}

// RequestedEvent represents an event with filters requested by a signature
type RequestedEvent struct {
	Type     string      // InputSource type of the requested event
	EvFilter EventFilter // Request for specific event and filters
}

type Filter struct {
	ArgName    string // ArgName refers to a name of an argument of the event
	ArgType    string
	Operator   string
	MatchValue interface{}
}

type SigResult struct {
	Match    bool
	Severity string // todo: change to enum
	Iocs     []Ioc
}

type Ioc struct {
	IocType    string // todo: change to enum
	Value      interface{}
	Properties map[string]string // todo: change to enum (property name and value)
}

type InputSource interface {
	// Return an event with the results of the evaluated filters (optional)
	GetEvent() (Event, []bool, error)
	Close()
}

type Event struct {
	Type string // which input source
	Name string
	Data interface{}
}

// New creates a new Sigengine instance based on a given valid SignaturesConfig
func New(cfg SignaturesConfig) (*Sigengine, error) {
	var err error

	// create sigengine
	s := &Sigengine{
		config: cfg,
	}

	// create instances of each signature class (go, opa)
	s.sigClasses = make(map[string]signatureClass)
	s.sigClasses["go"] = new(goSigClass)
	s.sigClasses["opa"] = new(opaSigClass)

	var filters []EventFilter

	if len(cfg.InputSources) == 0 {
		return nil, fmt.Errorf("No input sources given. At least one input source should be chosen\n")
	}

	for _, inputSrc := range cfg.InputSources {
		if strings.HasPrefix(inputSrc, "tracee") {
			inData := strings.Split(inputSrc, ":")
			if len(inData) != 2 || inData[0] != "tracee" {
				return nil, fmt.Errorf("Invalid tracee input source format. Should be tracee:PATH, but %s was given\n", inputSrc)
			}
			traceeIS, err := NewTraceeIS(inData[1], filters)
			if err != nil {
				s.Close()
				return nil, err
			}

			s.InputSources = make(map[string]InputSource)
			s.InputSources["tracee"] = traceeIS
		} else {
			return nil, fmt.Errorf("Unknown input source given: %s\n", inputSrc)
		}
	}

	s.sourceToReqs = make(map[string][]sigReq)

	err = s.initEngine()
	if err != nil {
		s.Close()
		return nil, err
	}

	return s, nil
}

func (s *Sigengine) printList() error {
	// todo: sort by category(?), add tags and other metadata
	fmt.Printf("%-6s %-20s %-20s %s\n", "Class", "Name", "Tags", "Description")

	for className, class := range s.sigClasses {
		sigsMetadata := class.getSigList()

		for _, sigMetadata := range sigsMetadata {
			fmt.Printf("%-6s %-20s %-20s %s\n", className, sigMetadata.Name, strings.Join(sigMetadata.Tags, ","), sigMetadata.Description)
		}
	}

	return nil
}

func (s *Sigengine) initEngine() error {
	if s.config.PrintSigList {
		return s.printList()
	}

	for className, class := range s.sigClasses {
		// Get all available signature names of the class
		var sigNames []string
		sigsMetadata := class.getSigList()
		for _, sigMeta := range sigsMetadata {
			sigNames = append(sigNames, sigMeta.Name)
		}

		// Initialize all the signatures of the class
		// todo: allow the user select which signatures will be used - default to all
		err := class.initSigs(sigNames)
		if err != nil {
			return fmt.Errorf("Failed to initialize sigengine: %v", err)
		}

		classReqEvents, err := class.getSigReqEvents(sigNames)
		if err != nil {
			return fmt.Errorf("Failed to get %s class requested events: %v", className, err)
		}

		for _, sigMeta := range sigsMetadata {
			for _, sigReqEv := range classReqEvents[sigMeta.Name] {
				// For every signature in class, get its requested events and save to sourceToReqs
				var sigReq sigReq
				sigReq.sigMeta = sigMeta
				sigReq.sigClass = class
				sigReq.evFilter = sigReqEv.EvFilter

				inputType := sigReqEv.Type
				s.sourceToReqs[inputType] = append(s.sourceToReqs[inputType], sigReq)
			}
		}
	}

	return nil
}

// Run starts the signatures engine. it will run until interrupted
func (s *Sigengine) Run() error {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	//s.printer.Preamble()
	for in, _ := range s.InputSources {
		go s.processEvents(in)
	}
	<-sig
	//s.printer.Epilogue(s.stats)
	s.Close()
	return nil
}

func (s *Sigengine) processEvents(in string) error {
	inSrc := s.InputSources[in]

	for {
		// todo: handle filtering (returned from GetEvent())
		event, _, err := inSrc.GetEvent()

		if err != nil {
			// todo: update error counter instead of printing error
			fmt.Printf("Input source %s err: %v\n", err)
		}

		// Dispatch the event to the relevant signature class using sourceToReqs
		for _, sigReq := range s.sourceToReqs[in] {
			// todo: currently we only check for name. Support event filtering by arguments as well
			if sigReq.evFilter.Name == event.Name {
				// todo: run signatures in parallel when onEvent is called!
				sigRes, err := sigReq.sigClass.onEvent(sigReq.sigMeta.Name, event)
				if err != nil {
					// todo: print error or update error counter
				}

				fmt.Printf("%+v\n", event)
				fmt.Printf("Res: %+v\n", sigRes)

				// todo: print the result returned from the signatures if required
				//s.printer.Print(event)
			}
		}
	}
}

// Close cleans up created resources
func (s *Sigengine) Close() {
	for _, in := range s.InputSources {
		in.Close()
	}

	// Todo: should we also close sig classes gracefully?
}

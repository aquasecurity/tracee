package formatter

import (
	pb "github.com/aquasecurity/tracee/api/v1beta1"
)

// PrintJSON prints an event in JSON format
func (f *Formatter) PrintStreamJSON(event *pb.Event) {
	//TODO: add more output formats
	f.CMD.Printf("%s", event.String())
}

func (f *Formatter) PrintEventListJSON(list *pb.GetEventDefinitionsResponse) {
	//TODO: add more output formats
	f.CMD.Printf("%s", list.String())
}

func (f *Formatter) PrintEventDescriptionJSON(description *pb.GetEventDefinitionsResponse) {
	//TODO: add more output formats
	f.CMD.Printf("%s", description.String())
}

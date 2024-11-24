package formatter

import (
	pb "github.com/aquasecurity/tracee/api/v1beta1"
)

func (f *Formatter) PrintStreamJSON(event *pb.Event) {
	f.CMD.Printf("%s", event.String())
}

func (f *Formatter) PrintEventListJSON(list *pb.GetEventDefinitionsResponse) {
	f.CMD.Printf("%s", list.String())
}

func (f *Formatter) PrintEventDescriptionJSON(description *pb.GetEventDefinitionsResponse) {
	f.CMD.Printf("%s", description.String())
}

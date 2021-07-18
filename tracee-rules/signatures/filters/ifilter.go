/*
A filter class is a class that helps to reduce the amount of signatures analyzing a certain event.
Each signature contains information about the events it expects to analyze, and by preprocessing
the event metadata some of the workload could be prevented.
Each filter should work as the following:
- Register all loaded signatures on initialization, by assigning them with a UID according to their index in the signatures array.
- Be able to load new signature or unload existing one with a given UID
- Create a bitmap representing which signature should be called according to a given event (the signature UID will be represented as the bit index in the bitmap).
A filter should contain a minimal logic during runtime, so it is recommended to create sets of bitmaps upon initialization and change them in loading or unloading of signatures.
The reason for using bitmaps is so multiple filters could work together with AND logic to receive final list of signatures to be called.
*/
package filter

import (
	"github.com/RoaringBitmap/roaring"
	tracee "github.com/aquasecurity/tracee/tracee-ebpf/tracee/external"
)

type Filter interface {
	// A method to get a matching bitmap filter for the loaded signatures according to the event occured.
	filterByEvent(filteredEvent tracee.Event) (*roaring.Bitmap, error)
}

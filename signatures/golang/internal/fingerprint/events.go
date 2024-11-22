package fingerprint

import (
	"github.com/aquasecurity/tracee/types/detect"
)

var FilesystemActivityEvents = &[...]detect.SignatureEventSelector{
	{Source: "tracee", Name: "file_modification", Origin: "*"},
}

var NetworkActivityEvents = &[...]detect.SignatureEventSelector{}

// var SyscallEvents = &[...]detect.SignatureEventSelector{
//     {Source: "tracee", Name: "", Origin: "*"},
// }

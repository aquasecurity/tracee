package detectors

// Example detector demonstrating the auto-registration pattern.
// Real detectors will be implemented in future commits.
//
// To add a new detector:
// 1. Create a new file in this package (e.g., my_detector.go)
// 2. Implement the detection.EventDetector interface
// 3. Add init() function that calls register(detector)
// 4. That's it! The detector will automatically be discovered and registered.
//
// Example:
//
//	func init() {
//	    register(&MyDetector{})
//	}
//
//	type MyDetector struct {
//	    // fields
//	}
//
//	func (d *MyDetector) GetDefinition() detection.DetectorDefinition {
//	    return detection.DetectorDefinition{
//	        ID:   "DET-001",
//	        Name: "My Detector",
//	        // ... other fields
//	    }
//	}
//
//	// Implement Init(), OnEvent(), OnSignal(), Close() methods...

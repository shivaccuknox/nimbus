package types

// == //

// K8sResourceTypes
const (
	K8sResourceTypeUnknown = 0
	K8sResourceTypePod     = 1
	K8sResourceTypeService = 2
)

// K8sResource Structure
type K8sResource struct {
	Type       uint8             `json:"type" bson:"type"`
	Namespace  string            `json:"namespace" bson:"namespace"`
	Name       string            `json:"name" bson:"name"`
	Labels     map[string]string `json:"labels" bson:"labels"`
	Containers []string          `json:"containers" bson:"containers"`
}

// K8sResourceTypeToString Function
func K8sResourceTypeToString(resourceType uint8) string {
	switch resourceType {
	case K8sResourceTypePod:
		return "Pod"
	case K8sResourceTypeService:
		return "Service"
	case K8sResourceTypeUnknown:
		return "Unknown"
	}
	return "Unknown"
}

// == //

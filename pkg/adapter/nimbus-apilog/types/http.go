package types

import "fmt"

// NetworkDevice Structure
type NetworkDevice struct {
	IPAddr        string      `json:"ip_addr" bson:"ip_addr"`
	Port          uint        `json:"port" bson:"port"`
	IsK8sResource bool        `json:"is_k8s_resource" bson:"is_k8s_resource"`
	Resource      K8sResource `json:"resource" bson:"resource"`
}

// HTTPRequest structure
type HTTPRequest struct {
	Src     NetworkDevice `json:"src" bson:"src"`
	Dst     NetworkDevice `json:"dst" bson:"dst"`
	Method  string        `json:"method" bson:"method"`
	Path    string        `json:"path" bson:"path"`
	Version string        `json:"version" bson:"version"`
}

// HTTPResponse structure
type HTTPResponse struct {
	Src          NetworkDevice `json:"src" bson:"src"`
	Dst          NetworkDevice `json:"dst" bson:"dst"`
	ResponseCode int           `json:"response_code" bson:"response_code"`
	Version      string        `json:"version" bson:"version"`
}

// ToString Function
func (nd *NetworkDevice) ToString() string {
	if nd.IsK8sResource {
		strType := K8sResourceTypeToString(nd.Resource.Type)
		return fmt.Sprintf("%s:%d (%s/%s, %s)",
			nd.IPAddr, nd.Port, nd.Resource.Namespace, nd.Resource.Name, strType)
	} else {
		return fmt.Sprintf("%s:%d", nd.IPAddr, nd.Port)
	}
}

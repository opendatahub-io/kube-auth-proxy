package authdeny

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/opendatahub-io/kube-auth-proxy/v1/pkg/logger"
)

const (
	applicationJSON              = "application/json"
	mlflowClientUserAgentPrefix  = "mlflow-python-client/"
	mlflowUnauthenticatedMessage = "Authentication to the MLflow tracking server failed. " +
		"Ensure you are logged in to the OpenShift cluster with `oc login`, have selected the " +
		"correct project/MLflow workspace with `oc project`, are using MLflow Python " +
		"client 3.11+, and have set MLFLOW_TRACKING_AUTH=kubernetes-namespaced to " +
		"automatically use your OpenShift credentials."
)

type mlflowHandler struct{}

func NewMLflowHandler() Handler {
	return mlflowHandler{}
}

func (mlflowHandler) Handle(rw http.ResponseWriter, req *http.Request, statusCode int) bool {
	if !strings.HasPrefix(req.Header.Get("User-Agent"), mlflowClientUserAgentPrefix) {
		return false
	}

	switch statusCode {
	case http.StatusUnauthorized:
		logger.Printf("No valid authentication in MLflow SDK request. Access Denied.")
		writeErrorJSON(rw, statusCode, "UNAUTHENTICATED", mlflowUnauthenticatedMessage)
		return true
	default:
		return false
	}
}

func writeErrorJSON(rw http.ResponseWriter, code int, errorCode string, message string) {
	rw.Header().Set("Content-Type", applicationJSON)
	rw.WriteHeader(code)

	if errorCode == "" && message == "" {
		// We need to send some JSON response because we set the Content-Type to
		// application/json.
		_, _ = rw.Write([]byte("{}"))
		return
	}

	_ = json.NewEncoder(rw).Encode(map[string]string{
		"error_code": errorCode,
		"message":    message,
	})
}

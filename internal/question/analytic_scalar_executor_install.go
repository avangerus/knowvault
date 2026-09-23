package question

import (
	"knowvault.local/verified-workspace/internal/analyticsource"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

// installAnalyticScalarExecutor is the one-shot install of the private scalar
// executor over an already-installed analytic capability. It requires a non-nil
// Service whose retained catalog is a valid installed snapshot, a non-nil
// retained resolver, a non-nil concrete authorized reader and an empty executor
// slot; every other input returns the bare CodeInvalid refusal.
//
// It calls analyticsource.NewScalarExecutor exactly once, with the retained
// resolver and the received reader, and assigns the slot only after that
// constructor returned without error. A refusal therefore mutates nothing and
// no caller can hold a partially installed executor.
func (service *Service) installAnalyticScalarExecutor(reader *workspacerepository.PostgreSQLAuthorizedReader) error {
	if service == nil || !service.datasetProfileCatalog.Valid() ||
		service.analyticSourceResolver == nil || reader == nil ||
		service.analyticScalarExecutor != nil {
		return &Error{code: CodeInvalid}
	}
	executor, err := analyticsource.NewScalarExecutor(service.analyticSourceResolver, reader)
	if err != nil {
		return &Error{code: CodeInvalid}
	}
	service.analyticScalarExecutor = executor
	return nil
}

// EnableAnalyticScalarExecutor installs the production scalar executor over
// the already-installed analytic capability and the supplied authorized
// reader.
func (service *Service) EnableAnalyticScalarExecutor(reader *workspacerepository.PostgreSQLAuthorizedReader) error {
	return service.installAnalyticScalarExecutor(reader)
}

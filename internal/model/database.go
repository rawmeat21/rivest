package model

type AccountDatabase struct {
	accounts          map[string]*Account // map by ID of Account
	byService         map[string][]string // maps Service names to their account IDs, useful for fetching all accounts for a service
	byIdentifierValue map[string][]string // maps indentifier values to account IDs, userful for fetching all accounts for an identifier like email
}

func (ad *AccountDatabase) Add(a *Account) error
func (ad *AccountDatabase) Find(service string, identifierValue string) (*Account, error)
func (ad *AccountDatabase) ListByService(service string) []*Account
func (ad *AccountDatabase) SuggestServices(prefix string) []string

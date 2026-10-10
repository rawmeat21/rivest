package model

import (
	"fmt"
	"slices"
)

type identKey struct {
	service string
	kind    IdentifierKind
	value   string
}

type AccountDatabase struct {
	accounts          map[string]*Account // map by ID of Account
	byService         map[string][]string // maps Service names to their account IDs, search by service
	byIdentifierValue map[string][]string // maps indentifier values to a list account IDs, search by identifier value only
	identOwner        map[identKey]string // maps to a single account ID, (service, identifier kind, identifier value) uniquely identifies any account
}

func NewAccountDatabase() *AccountDatabase {
	return &AccountDatabase{
		accounts:          make(map[string]*Account),
		byService:         make(map[string][]string),
		byIdentifierValue: make(map[string][]string),
		identOwner:        make(map[identKey]string),
	}
}

func (ad *AccountDatabase) Add(a *Account) error {
	if a == nil || a.ID == "" || len(a.Identifiers) == 0 {
		return ErrInvalidAccount
	}

	service := NormalizeService(a.Service)

	if service == "" {
		return fmt.Errorf("%w: empty service", ErrInvalidAccount)
	}

	if _, exists := ad.accounts[a.ID]; exists {
		return fmt.Errorf("%w: An account with the same ID exists", ErrDuplicateID)
	}

	seen := make(map[Identifier]bool)

	for _, i := range a.Identifiers {

		if i.Key() == "" {
			return fmt.Errorf("%w: identifier cannot be empty", ErrInvalidAccount)
		}

		if seen[NewIdentifier(i.Kind, i.Key())] {
			return fmt.Errorf("%w: Account contains duplicate identifier(s)", ErrDuplicateIdentifier)
		}

		// we cannot allow 2 same identifiers (for exact same service) to exist. Identifiers are like
		// primary keys for accounts in one service's scope, so we need to disallow duplicate identifiers
		// for one service
		if _, entry := ad.identOwner[identKey{service, i.Kind, i.Key()}]; entry {
			return fmt.Errorf("%w: %s", ErrDuplicateIdentifier, i.Value)
		}

		seen[NewIdentifier(i.Kind, i.Key())] = true
	}

	fseen := make(map[string]bool)
	for _, f := range a.Fields {

		name := NormalizeField(f.Name)

		if name == "" {
			return fmt.Errorf("%w: field name cannot be empty", ErrInvalidAccount)
		}

		if fseen[name] {
			return fmt.Errorf("%w: %s", ErrDuplicateField, name)
		}

		fseen[name] = true
	}

	ad.accounts[a.ID] = a
	ad.byService[service] = append(ad.byService[service], a.ID)

	indexed := make(map[string]bool)
	for _, i := range a.Identifiers {
		ad.identOwner[identKey{service, i.Kind, i.Key()}] = a.ID
		if !indexed[i.Key()] {
			indexed[i.Key()] = true
			ad.byIdentifierValue[i.Key()] = append(ad.byIdentifierValue[i.Key()], a.ID)
		}
	}

	return nil
}

func (ad *AccountDatabase) idsToAccounts(ids []string, predicate func(a *Account) bool) []*Account {

	var accounts []*Account
	for _, id := range ids {
		if a := ad.accounts[id]; predicate == nil || predicate(a) {
			accounts = append(accounts, a)
		}
	}
	return accounts
}

func (ad *AccountDatabase) idsByValue(value string) []string {

	var ids []string
	for _, key := range NormalizeSearch(value) {
		for _, id := range ad.byIdentifierValue[key] {
			if !slices.Contains(ids, id) {
				ids = append(ids, id)
			}
		}
	}

	return ids
}

func (ad *AccountDatabase) ListByService(service string) []*Account {
	return ad.idsToAccounts(ad.byService[NormalizeService(service)], nil)
}

func (ad *AccountDatabase) ListByIdentifierValue(value string, predicate func(a *Account) bool) []*Account {
	return ad.idsToAccounts(ad.idsByValue(value), predicate)
}

func (ad *AccountDatabase) FindByIdentifierValue(value string) []*Account {
	return ad.ListByIdentifierValue(value, nil)
}

func (ad *AccountDatabase) FindByIdentifier(ident Identifier) []*Account {

	key := ident.Key()

	return ad.ListByIdentifierValue(key, func(a *Account) bool {
		for _, i := range a.Identifiers {
			if i.Key() == key && i.Kind == ident.Kind {
				return true
			}
		}
		return false
	})
}

func (ad *AccountDatabase) FindByServiceAndIdentifierValue(service string, value string) []*Account {
	svc := NormalizeService(service)
	return ad.ListByIdentifierValue(value, func(a *Account) bool {
		return NormalizeService(a.Service) == svc
	})
}

func (ad *AccountDatabase) FindByServiceAndIdentifier(service string, ident Identifier) (*Account, bool) {
	if id, ok := ad.identOwner[identKey{NormalizeService(service), ident.Kind, ident.Key()}]; ok {
		return ad.accounts[id], true
	}

	return nil, false
}

func (ad *AccountDatabase) Update(acID string, updateMethod func(a *Account) error) {

}

func (ad *AccountDatabase) index(a *Account) {

}

func (ad *AccountDatabase) unindex(a *Account) {

}

func (ad *AccountDatabase) validate(a *Account) {

}

// func (ad *AccountDatabase) SuggestServices(prefix string) []string {

// }

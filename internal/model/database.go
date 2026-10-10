package model

import (
	"fmt"
	"slices"
	"strings"
	"time"
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

	// validate
	if err := ad.validate(a); err != nil {
		return err
	}

	if _, exists := ad.accounts[a.ID]; exists {
		return fmt.Errorf("%w: %s", ErrDuplicateID, a.ID)
	}

	// index
	ad.index(a)
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

func (ad *AccountDatabase) Update(acID string, updateMethod func(a *Account) error) error {
	// create clone, apply update, unindex old account, set old to point to clone, index again

	if updateMethod == nil {
		return ErrInvalidAccount
	}

	old, ok := ad.accounts[acID]

	if !ok {
		return fmt.Errorf("%w: account %s", ErrNotFound, acID)
	}

	// 1
	cp := old.clone()

	// 2
	if err := updateMethod(cp); err != nil {
		return err
	}

	// just ensuring updateMethod doesn't change these members
	cp.ID = old.ID
	cp.Created = old.Created

	// check if updated account is ok
	if err := ad.validate(cp); err != nil {
		return err
	}

	cp.Updated = time.Now().UTC()

	// 3
	ad.unindex(old)
	old.wipe()

	// 4

	/*
		old = cp; has a problem, any code that still points to the account pointed by old would see unmodified data, which is weird,
		because the data was just modified. The data has been modified for sure, if the user were to get the account again, they would
		see the modified data, but right now, the user is looking at an old object which has been unindexed. The fix is to
		copy all the data in the modified clone's struct, that way user would see an updated view and it will all be consistent.
	*/
	*old = *cp

	// 5
	ad.index(old)
	return nil
}

func (ad *AccountDatabase) Remove(acID string) error {
	a, ok := ad.accounts[acID]
	if !ok {
		return fmt.Errorf("%w: account %s", ErrNotFound, acID)
	}

	ad.unindex(a)
	a.wipe()
	*a = Account{}
	return nil
}

func (ad *AccountDatabase) index(a *Account) {
	service := NormalizeService(a.Service)
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
}

func removeID(mp map[string][]string, key, id string) {

	mp[key] = slices.DeleteFunc(mp[key], func(x string) bool {
		return x == id
	})

	if len(mp[key]) == 0 {
		delete(mp, key)
	}
}

func (ad *AccountDatabase) unindex(a *Account) {

	service := NormalizeService(a.Service)
	removeID(ad.byService, service, a.ID)

	for _, i := range a.Identifiers {
		delete(ad.identOwner, identKey{service, i.Kind, i.Key()})
		removeID(ad.byIdentifierValue, i.Key(), a.ID)
	}
	delete(ad.accounts, a.ID)
}

func (ad *AccountDatabase) validate(a *Account) error {
	if a == nil || a.ID == "" || len(a.Identifiers) == 0 {
		return ErrInvalidAccount
	}

	service := NormalizeService(a.Service)

	if service == "" {
		return fmt.Errorf("%w: empty service", ErrInvalidAccount)
	}

	seen := make(map[Identifier]bool)

	for _, i := range a.Identifiers {

		if i.Kind == "" || i.Key() == "" {
			return fmt.Errorf("%w: identifier cannot be empty", ErrInvalidAccount)
		}

		if seen[NewIdentifier(i.Kind, i.Key())] {
			return fmt.Errorf("%w: Account contains duplicate identifier(s)", ErrDuplicateIdentifier)
		}

		if id, entry := ad.identOwner[identKey{service, i.Kind, i.Key()}]; entry && id != a.ID {
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

	return nil
}

// func (ad *AccountDatabase) SuggestServices(prefix string) []string {

// }

func (ad *AccountDatabase) All() []*Account {
	list := make([]*Account, 0, len(ad.accounts))

	for _, a := range ad.accounts {
		list = append(list, a)
	}

	slices.SortFunc(list, func(x *Account, y *Account) int {
		if c:= x.Created.Compare(y.Created); c != 0 {
			return c
		}

		return strings.Compare(x.ID, y.ID)
	})

	return list
}
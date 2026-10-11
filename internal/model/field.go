package model

/*

Fields are data for an account that we want to store.
Fields can be passwords or other personal details
Can be encrypted and stored.

*/

type Field struct {
	Name        string `json:"name"`
	Value       []byte `json:"value"`
	IsEncrypted bool   `json:"encrypted"`
}

func NewField(name string, value []byte, isEncrypted bool) Field {
	return Field{
		Name:        name,
		Value:       value,
		IsEncrypted: isEncrypted,
	}
}

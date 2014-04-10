package mcassoc

import (
	"image"
)

type Associfier struct {
	key string
}

func (a Associfier) Verify(data string, skin image.Image) (bool, error) {
	return Verify(data, a.key, skin)
}

func (a Associfier) Embed(data string, skin image.Image) (image.Image, error) {
	return Embed(data, a.key, skin)
}

func (a Associfier) generateDatablock(data string) (image.Image, error) {
	return GenerateDatablock(data, a.key)
}

func NewAssocifier(key string) Associfier {
	return Associfier{
		key: key,
	}
}

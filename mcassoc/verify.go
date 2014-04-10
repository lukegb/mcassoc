package mcassoc

import (
	"image"
)

func Verify(data string, key string, skin image.Image) (bool, error) {
	db, err := GenerateDatablock(data, key)
	if err != nil {
		return false, err
	}

	// at the moment I just cheat and take the entire skin
	// this is OK for the moment, but in future if the DB needs to go somewhere else, we might have issues

	return CompareDatablocks(db, skin), nil
}

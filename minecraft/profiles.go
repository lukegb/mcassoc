package minecraft

import (
	"encoding/base64"
	"encoding/json"
)

type ProfileTextureData struct {
	Url string
}

type ProfilePropertyTextures struct {
	Timestamp   uint64
	ProfileId   string
	ProfileName string
	IsPublic    bool
	Textures    map[string]ProfileTextureData
}

type ProfileProperty struct {
	Name      string
	Value     string
	Signature string
}

type Profile struct {
	Id         string
	Name       string
	Properties []ProfileProperty
}

func (pc Profile) Textures() (*ProfilePropertyTextures, error) {
	for _, pp := range pc.Properties {
		if pp.Name == "textures" {
			decValue, err := base64.StdEncoding.DecodeString(pp.Value)
			if err != nil {
				return nil, err
			}

			pps := new(ProfilePropertyTextures)
			err = json.Unmarshal(decValue, &pps)
			if err != nil {
				return nil, err
			}

			return pps, nil
		}
	}

	return nil, ERR_HAS_NO_SKIN
}

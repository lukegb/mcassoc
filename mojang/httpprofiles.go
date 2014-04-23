package mojang

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

const (
	PROFILES_PER_REQUEST = 100
	MOJANG_SERVER        = "https://api.mojang.com"
	PROFILE_URL_FMT      = "%s/profiles/minecraft"
	LOG_TAG              = "[HttpProfileRepository]"
)

type HttpProfileRepository struct {
	c *http.Client
}

func (hpr HttpProfileRepository) GetProfilesByUsername(usernames []string) (profiles []Profile, err error) {
	log.Println(LOG_TAG, "fetching profiles by usernames:", usernames)

	for startAt := 0; startAt < len(usernames); startAt += PROFILES_PER_REQUEST {
		endAt := startAt+PROFILES_PER_REQUEST
		if endAt > len(usernames) {
			endAt = len(usernames)
		}

		var jsonCriteria []byte
		if jsonCriteria, err = json.Marshal(usernames[startAt : endAt]); err != nil {
			return nil, err
		}

		if res, err := hpr.getProfilesByUsernamePage(jsonCriteria); err != nil {
			return profiles, err
		} else {
			profiles = append(profiles, res...)
		}
	}

	return
}

func (hpr HttpProfileRepository) getProfilesByUsernamePage(jsonCriteria []byte) ([]Profile, error) {
	var resp *http.Response
	var err error

	r := bytes.NewReader(jsonCriteria)
	targetUrl := fmt.Sprintf(PROFILE_URL_FMT, MOJANG_SERVER)
	if resp, err = hpr.c.Post(targetUrl, "application/json", r); err != nil {
		return []Profile{}, err
	}
	defer resp.Body.Close()

	var retBytes []byte
	retBytes, err = ioutil.ReadAll(resp.Body)

	result := make([]Profile, 0)
	if err = json.Unmarshal(retBytes, &result); err != nil {
		return []Profile{}, err
	}

	return result, nil
}

func NewHttpProfileRepository() HttpProfileRepository {
	return HttpProfileRepository{
		c: http.DefaultClient,
	}
}

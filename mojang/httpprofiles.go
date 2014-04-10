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
	MAX_PAGES_TO_CHECK = 100
	MOJANG_SERVER      = "https://api.mojang.com"
	PROFILE_URL_FMT    = "%s/profiles/page/%d"
	LOG_TAG            = "[HttpProfileRepository]"
)

type HttpProfileRepository struct {
	c *http.Client
}

type httpProfileRepositoryResult struct {
	Profiles []Profile
	Size     uint16
}

func (hpr HttpProfileRepository) GetProfilesByCriteria(pc []ProfileCriteria) (profiles []Profile, err error) {
	log.Println(LOG_TAG, "fetching profiles by criteria:", pc)

	var jsonCriteria []byte
	if jsonCriteria, err = json.Marshal(pc); err != nil {
		return nil, err
	}

	for page := uint8(1); page < MAX_PAGES_TO_CHECK; page += 1 {
		if res, err := hpr.getProfilesByCriteriaPage(jsonCriteria, page); err != nil {
			return profiles, err
		} else {
			if res.Size == 0 {
				break
			}

			profiles = append(profiles, res.Profiles...)
		}
	}

	return
}

func (hpr HttpProfileRepository) getProfilesByCriteriaPage(jsonCriteria []byte, page uint8) (*httpProfileRepositoryResult, error) {
	var resp *http.Response
	var err error

	r := bytes.NewReader(jsonCriteria)
	targetUrl := fmt.Sprintf(PROFILE_URL_FMT, MOJANG_SERVER, page)
	if resp, err = hpr.c.Post(targetUrl, "application/json", r); err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var retBytes []byte
	retBytes, err = ioutil.ReadAll(resp.Body)

	result := new(httpProfileRepositoryResult)
	if err = json.Unmarshal(retBytes, result); err != nil {
		return nil, err
	}

	return result, nil
}

func NewHttpProfileRepository() HttpProfileRepository {
	return HttpProfileRepository{
		c: http.DefaultClient,
	}
}

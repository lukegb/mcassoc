package minecraft

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

const (
	SESSION_SERVER  = "https://sessionserver.mojang.com"
	PROFILE_URL_FMT = "%s/session/minecraft/profile/%s"
)

type ProfileClient struct {
	c *http.Client
}

func (pc ProfileClient) GetProfile(uuid string) (Profile, error) {
	var err error

	var resp *http.Response
	if resp, err = pc.c.Get(fmt.Sprintf(PROFILE_URL_FMT, SESSION_SERVER, uuid)); err != nil {
		return Profile{}, err
	}
	defer resp.Body.Close()

	var respBytes []byte
	respBytes, err = ioutil.ReadAll(resp.Body)

	var profile Profile
	if err = json.Unmarshal(respBytes, &profile); err != nil {
		return Profile{}, err
	}

	return profile, nil
}

func NewProfileClient() ProfileClient {
	return ProfileClient{
		c: http.DefaultClient,
	}
}

func GetProfile(uuid string) (Profile, error) {
	return NewProfileClient().GetProfile(uuid)
}

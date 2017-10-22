package minecraft

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"
)

const (
	SESSION_SERVER  = "https://sessionserver.mojang.com"
	PROFILE_URL_FMT = "%s/session/minecraft/profile/%s"
)

type ProfileCacheEntry struct {
	profile Profile
	expiry  time.Time
}

type ProfileCache map[string]ProfileCacheEntry

type ProfileClient struct {
	x ProfileCache
}

func (pc *ProfileClient) GetProfile(c *http.Client, uuid string) (Profile, error) {
	var err error

	log.Println("Requesting profile for", uuid)

	var resp *http.Response
	if resp, err = c.Get(fmt.Sprintf(PROFILE_URL_FMT, SESSION_SERVER, uuid)); err != nil {
		return Profile{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 204 || resp.StatusCode == 429 {
		if cacheEntry, ok := pc.x[uuid]; ok {
			return cacheEntry.profile, nil
		} else {
			return Profile{}, errors.New("mojang returned 204 when I have nothing cached!")
		}
	}

	var respBytes []byte
	respBytes, err = ioutil.ReadAll(resp.Body)

	log.Println("Got", string(respBytes), "with response code", resp.Status, "and headers", resp.Header)

	var profile Profile
	if err = json.Unmarshal(respBytes, &profile); err != nil {
		return Profile{}, err
	}

	// cache it
	cacheEntry := ProfileCacheEntry{
		profile: profile,
		expiry:  time.Now().Add(1 * time.Hour),
	}
	pc.x[uuid] = cacheEntry

	return profile, nil
}

func NewProfileClient() *ProfileClient {
	return &ProfileClient{
		x: make(ProfileCache),
	}
}

func GetProfile(c *http.Client, uuid string) (Profile, error) {
	return NewProfileClient().GetProfile(c, uuid)
}

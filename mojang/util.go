package mojang

import "net/http"

func GetProfileByUsername(c *http.Client, username string) (Profile, error) {
	hpr := NewHttpProfileRepository(c)
	profiles, err := hpr.GetProfilesByUsername([]string{username})
	if err != nil {
		return Profile{}, err
	} else if len(profiles) == 0 {
		return Profile{}, ERR_NO_SUCH_USER
	} else if len(profiles) > 1 {
		return Profile{}, ERR_TOO_MANY_RESULTS
	}
	return profiles[0], nil
}

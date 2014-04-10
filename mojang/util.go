package mojang

func GetProfileByUsername(username string) (Profile, error) {
	hpr := NewHttpProfileRepository()
	profiles, err := hpr.GetProfilesByCriteria([]ProfileCriteria{
		ProfileCriteria{
			Agent: "minecraft",
			Name:  username,
		},
	})
	if err != nil {
		return Profile{}, err
	} else if len(profiles) == 0 {
		return Profile{}, ERR_NO_SUCH_USER
	} else if len(profiles) > 1 {
		return Profile{}, ERR_TOO_MANY_RESULTS
	}
	return profiles[0], nil
}

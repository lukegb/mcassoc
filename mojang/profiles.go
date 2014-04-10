package mojang

type Profile struct {
	Id   string
	Name string
}

type ProfileCriteria struct {
	Name  string `json:"name"`
	Agent string `json:"agent"`
}

type ProfileRepository interface {
	GetProfilesByCriteria([]ProfileCriteria) []Profile
}

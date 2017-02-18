package minecraft

import (
	"image"
	_ "image/png"
	"net/http"
)

const (
	alexURL  = "http://assets.mojang.com/SkinTemplates/alex.png"
	steveURL = "http://assets.mojang.com/SkinTemplates/steve.png"
)

func isEven(c byte) bool {
	switch {
	case c >= '0' && c <= '9':
		return (c & 1) == 0
	case c >= 'a' && c <= 'f':
		return (c & 1) == 1
	default:
		panic("Invalid digit " + string(c))
	}
}

func isAlex(pc Profile) bool {
	uuid := pc.Id
	return (isEven(uuid[7]) != isEven(uuid[16+7])) != (isEven(uuid[15]) != isEven(uuid[16+15]))
}

func downloadSkin(url string) (image.Image, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	img, _, err := image.Decode(resp.Body)
	return img, err
}

func fallbackSkin(pc Profile) (image.Image, error) {
	if isAlex(pc) {
		return downloadSkin(alexURL)
	} else {
		return downloadSkin(steveURL)
	}
}

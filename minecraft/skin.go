package minecraft

import (
	"image"
	_ "image/jpeg"
	_ "image/png"
	"net/http"
)

func GetSkin(c *http.Client, pc Profile) (image.Image, error) {
	td, err := pc.Textures()
	switch {
	case err == ERR_HAS_NO_SKIN:
		return fallbackSkin(c, pc)
	case err != nil:
		return nil, err
	}

	if skin, ok := td.Textures["SKIN"]; !ok {
		return fallbackSkin(c, pc)
	} else {
		resp, err := c.Get(skin.Url)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		img, _, err := image.Decode(resp.Body)
		return img, err
	}
}

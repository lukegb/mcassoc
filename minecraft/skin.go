package minecraft

import (
	"image"
	"image/png"
	"net/http"
)

func GetSkin(c *http.Client, pc Profile) (image.Image, error) {
	td, err := pc.Textures()
	if err != nil {
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

		return png.Decode(resp.Body)
	}
}

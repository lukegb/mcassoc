package mcassoc

import (
	"image"
	"image/draw"
)

func Embed(data string, key string, skin image.Image) (image.Image, error) {
	sb := skin.Bounds()

	if sb.Dx() < DATABLOCK_WIDTH || sb.Dy() < DATABLOCK_HEIGHT {
		return nil, ERR_SKIN_TOO_SMALL
	}

	db, err := GenerateDatablock(data, key)
	if err != nil {
		return nil, err
	}

	// generate a new skin to work from
	outim := image.NewNRGBA(image.Rect(0, 0, sb.Dx(), sb.Dy()))
	draw.Draw(outim, sb, skin, image.Point{X: 0, Y: 0}, draw.Over)
	draw.Draw(outim, db.Bounds(), db, image.Point{X: 0, Y: 0}, draw.Over)

	return outim, nil
}

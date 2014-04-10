package mcassoc

import (
	"crypto/hmac"
	"crypto/sha1"
	"image"
	"image/color"
)

const (
	DATABLOCK_WIDTH  = 8
	DATABLOCK_HEIGHT = 8
)

func GenerateDatablock(data string, key string) (image.Image, error) {
	im := image.NewNRGBA(image.Rect(0, 0, DATABLOCK_WIDTH, DATABLOCK_HEIGHT))

	hash := hmac.New(sha1.New, []byte(key))
	hash.Write([]byte(data))
	result := hash.Sum([]byte{})

	for x := 0; x < DATABLOCK_WIDTH; x++ {
		for y := 0; y < DATABLOCK_HEIGHT; y++ {
			databytePos := (x + DATABLOCK_WIDTH*y) % len(result)

			im.Set(x, y, color.NRGBA{
				R: result[databytePos%len(result)],
				G: result[(databytePos+1)%len(result)],
				B: result[(databytePos+2)%len(result)],
				A: 255,
			})
		}
	}

	return im, nil
}

func CompareDatablocks(ours image.Image, theirs image.Image) bool {
	ob := ours.Bounds()
	tb := theirs.Bounds()

	cm := ours.ColorModel()

	// fail fast - this is OK
	if ob.Dx() < DATABLOCK_WIDTH || ob.Dy() < DATABLOCK_HEIGHT || tb.Dx() < DATABLOCK_WIDTH || tb.Dy() < DATABLOCK_HEIGHT {
		return false
	}

	isSame := true
	for x := 0; x < DATABLOCK_WIDTH; x++ {
		ox := ob.Min.X + x
		tx := tb.Min.X + x

		for y := 0; y < DATABLOCK_HEIGHT; y++ {
			oy := ob.Min.Y + y
			ty := tb.Min.Y + y

			oc := ours.At(ox, oy)
			tc := cm.Convert(theirs.At(tx, ty))

			if oc != tc {
				isSame = false
			}
		}
	}

	return isSame
}

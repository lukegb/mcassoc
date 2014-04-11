package mcassoc

import (
	"crypto/hmac"
	"crypto/sha512"
	"image"
	"image/color"
)

const (
	DATABLOCK_WIDTH  = 8
	DATABLOCK_HEIGHT = 8
)

var (
	PRESENCE_PATTERN = []color.NRGBA{
		color.NRGBA{0, 0, 0, 255},
		color.NRGBA{30, 0, 0, 255},
		color.NRGBA{0, 30, 0, 255},
		color.NRGBA{0, 0, 30, 255},
		color.NRGBA{30, 30, 0, 255},
		color.NRGBA{0, 30, 30, 255},
		color.NRGBA{30, 0, 30, 255},
		color.NRGBA{30, 30, 30, 255},
	}
)

func GenerateDatablock(data string, key string) (image.Image, error) {
	im := image.NewNRGBA(image.Rect(0, 0, DATABLOCK_WIDTH, DATABLOCK_HEIGHT))

	hash := hmac.New(sha512.New, []byte(key))
	hash.Write([]byte(data))
	result := hash.Sum([]byte{})

	for x := 0; x < DATABLOCK_WIDTH; x++ {
		for y := 1; y < DATABLOCK_HEIGHT; y++ {
			databytePos := (3 * (x + DATABLOCK_WIDTH*y)) % len(result)

			im.Set(x, y, color.NRGBA{
				R: result[databytePos%len(result)],
				G: result[(databytePos+1)%len(result)],
				B: result[(databytePos+2)%len(result)],
				A: 255,
			})
		}
	}

	// add the presence marker
	xw := DATABLOCK_WIDTH
	if len(PRESENCE_PATTERN) < xw {
		xw = len(PRESENCE_PATTERN)
	}
	for x := 0; x < xw; x++ {
		im.Set(x, 0, PRESENCE_PATTERN[x])
	}

	return im, nil
}

func HasDatablock(theirs image.Image) bool {
	tb := theirs.Bounds()

	cm := color.NRGBAModel

	// add the presence marker
	xw := DATABLOCK_WIDTH
	if len(PRESENCE_PATTERN) < xw {
		xw = len(PRESENCE_PATTERN)
	}
	for x := 0; x < xw; x++ {
		if cm.Convert(theirs.At(tb.Min.X+x, 0)) != PRESENCE_PATTERN[x] {
			return false
		}
	}
	return true
}

func CompareDatablocks(ours image.Image, theirs image.Image) bool {
	ob := ours.Bounds()
	tb := theirs.Bounds()

	cm := ours.ColorModel()

	// fail fast - this is OK since the attacker already knows the size of the secret
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

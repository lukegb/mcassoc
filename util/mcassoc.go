//+build skip

package main

import (
	mcassoc "github.com/lukegb/mcassoc/mcassoc"
	minecraft "github.com/lukegb/mcassoc/minecraft"
	mojang "github.com/lukegb/mcassoc/mojang"
	"image/png"
	"log"
	"os"
)

func main() {
	if len(os.Args) != 4 {
		log.Fatalln(os.Args[0], "<key> <MC username> <outfile>")
	}

	a := mcassoc.NewAssocifier(os.Args[1])

	profile, err := mojang.GetProfileByUsername(os.Args[2])
	if err != nil {
		log.Fatal("GetProfileByUsername", err)
	}
	log.Println("profile {name:", profile.Name, ", id:", profile.Id, "}")

	mcprofile, err := minecraft.GetProfile(profile.Id)
	if err != nil {
		log.Fatal(err)
	}
	log.Println(mcprofile)
	log.Println(mcprofile.Textures())

	img, err := minecraft.GetSkin(mcprofile)
	if err != nil {
		log.Fatal(err)
	}

	emimg, err := a.Embed(profile.Id, img)
	if err != nil {
		log.Fatal(err)
	}

	file, err := os.Create(os.Args[3])
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	if err = png.Encode(file, emimg); err != nil {
		log.Fatal(err)
	}
}

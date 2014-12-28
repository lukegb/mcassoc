package statkeeper

import (
	"github.com/stathat/go"
)

type StatKeeper interface {
	NewAssocAttempt()
	AssocComplete()
	AssocFail()
	MojangRequestOK()
	MojangRequestFail()
	McRequestOK()
	McRequestFail()
}

type VoidStatKeeper struct {
}

func (VoidStatKeeper) NewAssocAttempt()   {}
func (VoidStatKeeper) AssocComplete()     {}
func (VoidStatKeeper) AssocFail()         {}
func (VoidStatKeeper) MojangRequestOK()   {}
func (VoidStatKeeper) MojangRequestFail() {}
func (VoidStatKeeper) McRequestOK()       {}
func (VoidStatKeeper) McRequestFail()     {}

type StatHatStatKeeper struct {
	ezKey string
}

func NewStatHatStatKeeper(ezKey string) *StatHatStatKeeper {
	return &StatHatStatKeeper{
		ezKey: ezKey,
	}
}

func (sk *StatHatStatKeeper) count(name string, count int) {
	stathat.PostEZCount(name, sk.ezKey, count)
}

func (sk *StatHatStatKeeper) NewAssocAttempt() {
	sk.count("assoc start", 1)
}

func (sk *StatHatStatKeeper) AssocComplete() {
	sk.count("assoc complete", 1)
}

func (sk *StatHatStatKeeper) AssocFail() {
	sk.count("assoc fail", 1)
}

func (sk *StatHatStatKeeper) MojangRequestOK() {
	sk.count("mojang request ok", 1)
}

func (sk *StatHatStatKeeper) MojangRequestFail() {
	sk.count("mojang request fail", 1)
}

func (sk *StatHatStatKeeper) McRequestOK() {
	sk.count("minecraft request ok", 1)
}

func (sk *StatHatStatKeeper) McRequestFail() {
	sk.count("minecraft request fail", 1)
}

var GLOBAL StatKeeper = VoidStatKeeper{}

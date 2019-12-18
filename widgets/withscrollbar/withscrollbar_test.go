package withscrollbar

import (
	"fmt"
	"strings"
	"testing"

	"github.com/gcla/gowid"
	"github.com/gcla/gowid/gwtest"
	"github.com/gcla/gowid/widgets/button"
	"github.com/gcla/gowid/widgets/list"
	"github.com/gcla/gowid/widgets/text"
	"github.com/stretchr/testify/assert"
)

type scrollingListBox struct {
	*list.Widget
}

func (t *scrollingListBox) Up(lines int, size gowid.IRenderSize, app gowid.IApp)     {}
func (t *scrollingListBox) Down(lines int, size gowid.IRenderSize, app gowid.IApp)   {}
func (t *scrollingListBox) UpPage(num int, size gowid.IRenderSize, app gowid.IApp)   {}
func (t *scrollingListBox) DownPage(num int, size gowid.IRenderSize, app gowid.IApp) {}

func (t *scrollingListBox) ScrollLength() int {
	return 8
}

func (t *scrollingListBox) ScrollPosition() int {
	return 0
}

func Test1(t *testing.T) {
	bws := make([]gowid.IWidget, 8)
	for i := 0; i < len(bws); i++ {
		bws[i] = button.NewBare(text.New(fmt.Sprintf("%03d", i)))
	}

	walker := list.NewSimpleListWalker(bws)
	lbox := &scrollingListBox{Widget: list.New(walker)}
	sbox := New(lbox)

	canvas1 := sbox.Render(gowid.MakeRenderBox(4, 8), gowid.NotSelected, gwtest.D)
	res := strings.Join([]string{
		"000▲",
		"001█",
		"002 ",
		"003 ",
		"004 ",
		"005 ",
		"006 ",
		"007▼",
	}, "\n")
	assert.Equal(t, res, canvas1.String())

	sbox = New(lbox, Options{
		HideIfContentFits: true,
	})

	canvas1 = sbox.Render(gowid.MakeRenderBox(4, 8), gowid.NotSelected, gwtest.D)
	res = strings.Join([]string{
		"000 ",
		"001 ",
		"002 ",
		"003 ",
		"004 ",
		"005 ",
		"006 ",
		"007 ",
	}, "\n")
	assert.Equal(t, res, canvas1.String())

	canvas1 = sbox.Render(gowid.MakeRenderBox(4, 5), gowid.NotSelected, gwtest.D)
	res = strings.Join([]string{
		"000▲",
		"001█",
		"002 ",
		"003 ",
		"004▼",
	}, "\n")
	assert.Equal(t, res, canvas1.String())
}

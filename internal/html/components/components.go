package components

import (
	"fmt"
	"strings"
	"unicode"

	g "maragu.dev/gomponents"
	ghtmx "maragu.dev/gomponents-htmx"
	gh "maragu.dev/gomponents/html"

	mdb "github.com/liondandelion/metla/internal/db"
)

func Hyperscript(script string) g.Node {
	trimmed := strings.TrimLeftFunc(script, unicode.IsSpace)
	trimmed = strings.TrimRightFunc(trimmed, unicode.IsSpace)
	return g.Attr("_", trimmed)
}

func Navbar(username string, isAuthenticated, isAdmin bool) g.Node {
	return gh.Header(
		gh.Nav(gh.Class("navbar"),
			gh.Ul(gh.Class("navbar-left-side"),
				gh.Li(gh.Class("navbar-item"),
					gh.A(gh.Href("/"), gh.Class("left"), g.Text("Metla")),
				),
			),
			gh.Ul(gh.Class("navbar-right-side"),
				g.If(isAuthenticated,
					g.Group{
						gh.Li(gh.Class("navbar-item"),
							gh.A(gh.Href("/user"), g.Text(username)),
						),
						g.If(isAdmin,
							gh.Li(gh.Class("navbar-item"),
								gh.A(gh.Href("/userstable"), g.Text("Users")),
							),
						),
						gh.Li(gh.Class("navbar-item"),
							gh.A(gh.Href("/logout"), g.Text("Logout")),
						),
					},
				),
				g.If(!isAuthenticated,
					g.Group{
						gh.Li(gh.Class("navbar-item"),
							gh.A(gh.Href("/register"), g.Text("Register")),
						),
						gh.Li(gh.Class("navbar-item"),
							gh.A(gh.Href("/login"), g.Text("Login")),
						),
					},
				),
			),
		),
	)
}

func Error(id, message string) g.Node {
	return gh.Div(gh.ID(id), g.Text(message))
}

func FormOTP(postTo string) g.Node {
	return g.Group{
		gh.Form(gh.ID("otpForm"),
			gh.Label(gh.For("otpCode"), g.Text("OTP code: ")),
			gh.Input(gh.Type("text"), gh.Name("otpCode"), gh.ID("otpCode"), gh.Required(), gh.AutoFocus(),
				Hyperscript(`
					on load put '' into me
				`),
			),
			gh.Input(gh.Type("submit"), gh.Value("Send"), ghtmx.Post(postTo), ghtmx.Target("#serverResponse"), ghtmx.Swap("outerHTML"),
				Hyperscript(`
					on click wait 100ms then set value of #otpCode to ''
				`),
			),
			gh.Div(gh.ID("serverResponse")),
		),
	}
}

func EventList(events []mdb.Event, page int) g.Node {
	if len(events) == 0 {
		return g.Raw("")
	}

	f := func(e mdb.Event) g.Node {
		year, month, day := e.Date.Date()
		hour, minute, sec := e.Date.Clock()
		return gh.P(
			g.Text(e.Title),
			g.Text(fmt.Sprintf(" %02d.", day)), g.Text(fmt.Sprintf("%02d.", month)), g.Text(fmt.Sprintf("%v", year)),
			g.Text(fmt.Sprintf(" %02d:", hour)), g.Text(fmt.Sprintf("%02d:", minute)), g.Text(fmt.Sprintf("%02d", sec)),
		)
	}

	e := events[len(events)-1]
	year, month, day := e.Date.Date()
	hour, minute, sec := e.Date.Clock()

	return g.Group{
		g.Map(events[:len(events)-1], f),
		gh.P(ghtmx.Get(fmt.Sprintf("/user/event?page=%v", page+1)), ghtmx.Trigger("intersect once"), ghtmx.Swap("afterend"),
			g.Group{
				g.Text(e.Title),
				g.Text(fmt.Sprintf(" %02d.", day)), g.Text(fmt.Sprintf("%02d.", month)), g.Text(fmt.Sprintf("%v", year)),
				g.Text(fmt.Sprintf(" %02d:", hour)), g.Text(fmt.Sprintf("%02d:", minute)), g.Text(fmt.Sprintf("%02d", sec)),
			},
		),
	}
}

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
					gh.A(gh.Class("button-like"), gh.Href("/"), g.Text("Metla")),
				),
			),
			gh.Ul(gh.Class("navbar-right-side"),
				g.If(isAuthenticated,
					g.Group{
						gh.Li(gh.Class("navbar-item"),
							gh.A(gh.Class("button-like"), gh.Href("/user"), g.Text(username)),
						),
						g.If(isAdmin,
							gh.Li(gh.Class("navbar-item"),
								gh.A(gh.Class("button-like"), gh.Href("/userstable"), g.Text("Users")),
							),
						),
						gh.Li(gh.Class("navbar-item"),
							gh.A(gh.Class("button-like"), gh.Href("/logout"), g.Text("Logout")),
						),
					},
				),
				g.If(!isAuthenticated,
					g.Group{
						gh.Li(gh.Class("navbar-item"),
							gh.A(gh.Class("button-like"), gh.Href("/register"), g.Text("Register")),
						),
						gh.Li(gh.Class("navbar-item"),
							gh.A(gh.Class("button-like"), gh.Href("/login"), g.Text("Login")),
						),
					},
				),
			),
		),
	)
}

func Sidebar(isAuthenticated bool) g.Node {
	var sidebar g.Node

	if !isAuthenticated {
		sidebar = gh.Aside(gh.ID("sidebar"), gh.Class("sidebar"),
			gh.P(gh.Style("line-height: 2em;"),
				g.Text("There is nothing to show here yet. Please "),
				gh.A(gh.Class("button-like"), gh.Href("/register"), g.Text("register")),
				g.Text(" or "),
				gh.A(gh.Class("button-like"), gh.Href("/login"), g.Text("login")),
				g.Text(" to see more."),
			),
		)
	} else {
		sidebar = gh.Aside(gh.ID("sidebar"), gh.Class("sidebar"),
			gh.Div(gh.Class("sidebar-controls"),
				gh.Button(gh.ID("btnAddEvent"), g.Text("Add event"),
					ghtmx.Trigger("click"), ghtmx.Get("/user/event/new"), ghtmx.Swap("afterend"),
				),
			),
			gh.Div(gh.Class("sidebar-content"),
				AnchorEventNew(),
				AnchorEventLoadMore(0),
			),
		)
	}

	return sidebar
}

func Error(id, message string) g.Node {
	return gh.Div(gh.ID(id), g.Text(message))
}

func FormOTP(postTo string) g.Node {
	return g.Group{
		gh.Form(gh.ID("otpForm"), ghtmx.Post(postTo), ghtmx.Target("#serverResponse"), ghtmx.Swap("outerHTML"),
			gh.Label(gh.For("otpCode"), g.Text("OTP code: ")),
			gh.Input(gh.Type("text"), gh.Name("otpCode"), gh.ID("otpCode"), gh.Required(), gh.AutoFocus(),
				Hyperscript(`
					on load put '' into me
				`),
			),
			gh.Button(gh.Type("submit"),
				Hyperscript(`
					on click wait 100ms then set value of #otpCode to ''
				`),
				g.Text("Send"),
			),
			gh.Div(gh.ID("serverResponse")),
		),
	}
}

func EventCard(e mdb.Event) g.Node {
	year, month, day := e.Date.Date()
	hour, minute, sec := e.Date.Clock()

	return gh.Article(gh.Class("event-card"),
		gh.H1(g.Text(e.Title)),
		gh.H2(g.Text(e.Author)),
		gh.P(gh.Class("time"),
			g.Text(fmt.Sprintf(" %02d.", day)), g.Text(fmt.Sprintf("%02d.", month)), g.Text(fmt.Sprintf("%v", year)),
			g.Text(fmt.Sprintf(" %02d:", hour)), g.Text(fmt.Sprintf("%02d:", minute)), g.Text(fmt.Sprintf("%02d", sec)),
		),
	)
}

func AnchorEventLoadMore(nextPage int) g.Node {
	return gh.Article(ghtmx.Get(fmt.Sprintf("/user/event?page=%v", nextPage)), ghtmx.Trigger("intersect once"), ghtmx.Swap("afterend"))
}

func EventCardList(events []mdb.Event, page int) g.Node {
	if len(events) == 0 {
		return g.Raw("")
	}

	return g.Group{
		g.Map(events, EventCard),
		AnchorEventLoadMore(page + 1),
	}
}

func AnchorEventNew() g.Node {
	return gh.Article(gh.ID("anchorEventNew"))
}

func EventNew() g.Node {
	return gh.Form(gh.ID("formEventNew"), ghtmx.Post("/user/event/new"), ghtmx.Target("#anchorEventNew"), ghtmx.Swap("afterend"),
		Hyperscript(`
			on htmx:beforeSend remove me
		`),
		gh.Label(gh.For("title"), g.Text("Title: ")),
		gh.Input(gh.Type("text"), gh.Name("title"), gh.ID("title"), gh.Required()),
		gh.Label(gh.For("description"), g.Text("Description: ")),
		gh.Textarea(gh.Name("description"), gh.ID("description"), gh.Cols("35"), gh.Required()),
		gh.Label(gh.For("datetime"), g.Text("Date and time (optional): ")),
		gh.Input(gh.Type("datetime-local"), gh.Name("datetime"), gh.ID("datetime")),
		gh.Button(gh.Type("submit"),
			g.Text("Send"),
		),
	)
}

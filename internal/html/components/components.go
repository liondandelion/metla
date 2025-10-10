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
				gh.Li(
					gh.A(gh.Class("button-like"), gh.Href("/"), g.Text("Metla")),
				),
			),
			gh.Ul(gh.Class("navbar-right-side"),
				g.If(isAuthenticated,
					g.Group{
						gh.Li(
							gh.A(gh.Class("button-like"), gh.Href("/user"), g.Text(username)),
						),
						g.If(isAdmin,
							gh.Li(
								gh.A(gh.Class("button-like"), gh.Href("/userstable"), g.Text("Users")),
							),
						),
						gh.Li(
							gh.A(gh.Class("button-like"), gh.Href("/logout"), g.Text("Logout")),
						),
					},
				),
				g.If(!isAuthenticated,
					g.Group{
						gh.Li(
							gh.A(gh.Class("button-like"), gh.Href("/register"), g.Text("Register")),
						),
						gh.Li(
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
			gh.P(gh.Style("line-height: 2em; text-align: center;"),
				g.Text("There is nothing to show here yet. Please "),
				gh.A(gh.Class("button-like"), gh.Href("/register"), g.Text("register")),
				g.Text(" or "),
				gh.A(gh.Class("button-like"), gh.Href("/login"), g.Text("login")),
				g.Text(" to see more."),
			),
		)
	} else {
		sidebar = gh.Aside(gh.ID("sidebar"), gh.Class("sidebar"),
			gh.Div(gh.ID("sidebar-controls"), gh.Class("sidebar-controls"),
				Hyperscript(`
					on formEventNewClose set innerHTML of #formEventNew to "" then set innerHTML of #btnAddEvent to "Add event"
				`),
				gh.Button(gh.ID("btnAddEvent"),
					ghtmx.Trigger("fetchEvent"), ghtmx.Get("/user/event/new"), ghtmx.Target("#formEventNew"), ghtmx.Swap("outerHTML"),
					Hyperscript(`
						on click
							if my innerHTML equals "Add event"
								send cardCollapse to .event-card
								set my innerHTML to "Close event"
								trigger fetchEvent
							else if my innerHTML equals "Close event" then send formEventNewClose to #sidebar-controls
					`),
					g.Text("Add event"),
				),
				gh.Form(gh.ID("formEventNew")),
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
	return gh.Div(gh.Class("server-response"), gh.ID(id), g.Text(message))
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

func EventCard(e mdb.Event, isSmall bool) g.Node {
	var class, htmx, title, author, description, time, hyperscript, geojson g.Node

	if e.DatetimeStart == nil {
		time = nil
	} else {
		yearStart, monthStart, dayStart := e.DatetimeStart.Date()
		hourStart, minuteStart, _ := e.DatetimeStart.Clock()
		yearEnd, monthEnd, dayEnd := e.DatetimeEnd.Date()
		hourEnd, minuteEnd, _ := e.DatetimeEnd.Clock()

		time = gh.P(gh.Class("time"),
			g.Text(fmt.Sprintf(" %02d.", dayStart)), g.Text(fmt.Sprintf("%02d.", monthStart)), g.Text(fmt.Sprintf("%v", yearStart)),
			g.Text(fmt.Sprintf(" %02d:", hourStart)), g.Text(fmt.Sprintf("%02d", minuteStart)), g.Text(" UTC"),
			g.Text(fmt.Sprintf(" %02d.", dayEnd)), g.Text(fmt.Sprintf("%02d.", monthEnd)), g.Text(fmt.Sprintf("%v", yearEnd)),
			g.Text(fmt.Sprintf(" %02d:", hourEnd)), g.Text(fmt.Sprintf("%02d", minuteEnd)), g.Text(" UTC"),
		)
	}

	title = gh.H1(g.Text(e.Title))
	author = gh.H2(g.Text(e.Author))

	divID := fmt.Sprintf("%v-%v-geojson", e.Author, e.ID)

	if isSmall {
		class = gh.Class("event-card-small")
		htmx = g.Group{
			ghtmx.Get(fmt.Sprintf("/user/event/%v-%v", e.Author, e.ID)), ghtmx.Trigger("click"), ghtmx.Swap("outerHTML"),
		}
		hyperscript = Hyperscript(`
			on click call markerRemoveAll() then send cardCollapse to .event-card then send formEventNewClose to #sidebar-controls
		`)
		description = nil
		geojson = nil
	} else {
		class = gh.Class("event-card")
		htmx = g.Group{
			ghtmx.Get(fmt.Sprintf("/user/event/%v-%v?small", e.Author, e.ID)), ghtmx.Trigger("htmxCardCollapse"), ghtmx.Swap("outerHTML"),
		}
		hyperscript = Hyperscript(`
			on load call stringJSONToMarkers(` + `@data-geojson of #` + divID + `)
			on click send cardCollapse to .event-card
			on cardCollapse or click call markerRemoveAll() then trigger htmxCardCollapse
		`)
		description = gh.P(g.Text(e.Description))
		geojson = gh.Div(gh.ID(divID), g.Attr("data-geojson", e.GeoJSON))
	}

	return gh.Article(class, htmx, hyperscript, title, author, time, description, geojson)
}

func EventCardSmall(e mdb.Event) g.Node {
	return EventCard(e, true)
}

func EventCardNormal(e mdb.Event) g.Node {
	return EventCard(e, false)
}

func EventCardSmallList(events []mdb.Event, page int) g.Node {
	if len(events) == 0 {
		return g.Raw("")
	}

	return g.Group{
		g.Map(events, EventCardSmall),
		AnchorEventLoadMore(page + 1),
	}
}

func EventNew() g.Node {
	return gh.Form(gh.ID("formEventNew"), ghtmx.Post("/user/event/new"), ghtmx.Target("#anchorEventNew"), ghtmx.Swap("afterend"),
		Hyperscript(`
			on htmx:beforeSend set innerHTML of #serverResponse to ""
			on htmx:afterRequest
				if innerHTML of #serverResponse is ""
					call markerRemoveAll() then send formEventNewClose to #sidebar-controls
		`),
		gh.Label(gh.For("title"), g.Text("Title: ")),
		gh.Input(gh.Type("text"), gh.Name("title"), gh.ID("title"), gh.Required()),
		gh.Label(gh.For("description"), g.Text("Description: ")),
		gh.Textarea(gh.Name("description"), gh.ID("description"), gh.Cols("35"), gh.Required()),
		gh.Label(gh.For("datetimeStart"), g.Text("Starting at (optional): ")),
		gh.Input(gh.Type("datetime-local"), gh.Name("datetimeStart"), gh.ID("datetimeStart")),
		gh.Label(gh.For("datetimeEnd"), g.Text("Ending at (optional): ")),
		gh.Input(gh.Type("datetime-local"), gh.Name("datetimeEnd"), gh.ID("datetimeEnd")),
		gh.Input(gh.Type("hidden"), gh.Name("geojson"), gh.ID("geojson")),
		gh.Button(gh.Type("button"),
			Hyperscript(`
				on click call markerPlace()
			`),
			g.Text("Add marker"),
		),
		gh.Button(gh.Type("button"),
			Hyperscript(`
				on click call markerRemove()
			`),
			g.Text("Remove marker"),
		),
		gh.Button(gh.Type("submit"),
			Hyperscript(`
				on click call markerToGeoJSONString() then put the result into @value of #geojson
			`),
			g.Text("Send"),
		),
		gh.Div(gh.ID("serverResponse")),
	)
}

func EventNewError(id, message string) g.Node {
	return g.Group{
		AnchorEventNew(),
		gh.Div(gh.Class("server-response"), gh.ID(id), ghtmx.SwapOOB("outerHTML"), g.Text(message)),
	}
}

func AnchorEventLoadMore(nextPage int) g.Node {
	return gh.Article(ghtmx.Get(fmt.Sprintf("/user/event/page?page=%v", nextPage)), ghtmx.Trigger("intersect once"), ghtmx.Swap("afterend"))
}

func AnchorEventNew() g.Node {
	return gh.Article(gh.ID("anchorEventNew"))
}

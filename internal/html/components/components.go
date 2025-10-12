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

type EventCardParams struct {
	IsSmall bool
}

func Hyperscript(script string) g.Node {
	trimmed := strings.TrimLeftFunc(script, unicode.IsSpace)
	trimmed = strings.TrimRightFunc(trimmed, unicode.IsSpace)
	return g.Attr("_", trimmed)
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
			gh.Div(gh.ID("sidebarControls"), gh.Class("sidebar-controls"),
				Hyperscript(`
					on formEventNewClose
						set innerHTML of #formEventNew to "" then set innerHTML of #btnAddEvent to "Add event"
				`),
				gh.Button(gh.ID("btnAddEvent"),
					ghtmx.Trigger("fetchEvent"), ghtmx.Get("/user/event/new"), ghtmx.Target("#formEventNew"), ghtmx.Swap("outerHTML"),
					Hyperscript(`
						on click
							if my innerHTML equals "Add event"
								set my innerHTML to "Close event"
								send formEventNewOpen to .btn-link-this
								send activateContent to #sidebarContent
								trigger fetchEvent
							else if my innerHTML equals "Close event"
								send formEventNewClose to #sidebarControls
								send activateContent to #sidebarContent
								call markersFromNewRemove()
							end
						end

						on btnLinkThisClicked
							if my innerHTML equals "Add event" then send click to me
							else send newEventFormOpen to #btnLinkThis end
					`),
					g.Text("Add event"),
				),
				gh.Form(gh.ID("formEventNew")),
				gh.Button(gh.ID("btnSearchEvents"),
					g.Text("Search events"),
				),
				gh.Div(gh.Class("info-box"),
					gh.P(gh.ID("currentContentText"), gh.Class("current-content-text"),
						g.Text("Timeline"),
					),
					gh.Button(gh.ID("btnGoBackward"), gh.Class("btn-go-backward hidden"),
						ghtmx.Trigger("fetchHistory"), ghtmx.Target(".sidebar-content"), ghtmx.Swap("innerHTML"),
						Hyperscript(`
							on currentPage(url)
								set :currentURL to url
							end

							on pushURL(id)
								if no :backwardHistory set :backwardHistory to [] end
								if no :ids set :ids to [] end

								append :currentURL to :backwardHistory
								append id to :ids

								remove .hidden from me
							end

							on click
								halt the event's bubbling
								send cardCollapse to .event-card

								call :backwardHistory.pop() then set @hx-get to the result
								call :ids.pop() then set :id to it
								call htmx.process(me)

								send currentPage(url: @hx-get) to me
								if :backwardHistory is empty add .hidden to me end
								trigger fetchHistory
							end

							on shouldCardActivate
								if :id is not empty
									go to the middle of #{:id}
									send click to #{:id}
									set :id to ""
								end
							end

							on hide add .hidden to me end
							on unhide if :backwardHistory is not empty then remove .hidden from me
						`),
						g.Text("<-"),
					),
				),
			),
			gh.Div(gh.ID("sidebarContent"), gh.Class("sidebar-content"),
				Hyperscript(`
					on activateContent
						if I do not match .sidebar-content
							add .sidebar-content to me
							remove .hidden from me
							add .hidden to #sidebarContentLinks
							remove .sidebar-content from #sidebarContentLinks
							send cardCollapse to .event-card
							if #btnEventLinksView is not empty then send reset to #btnEventLinksView end
							send unhide to #btnGoBackward
							set innerHTML of #currentContentText to "Timeline"
						end
				`),
				AnchorEventLoadMore(0),
			),
			gh.Div(gh.ID("sidebarContentLinks"), gh.Class("hidden"),
				ghtmx.Trigger("fetchEvent2"), ghtmx.Swap("beforeend"),
				Hyperscript(`
					on addEventLink(eventID)
						set @hx-get to "/user/event/" + eventID + "?small" then call htmx.process(me)
						append eventID + " " to @value of #links
						trigger fetchEvent2
					end

					on activateContent
						if I do not match .sidebar-content
							add .sidebar-content to me
							remove .hidden from me
							add .hidden to #sidebarContent
							remove .sidebar-content from #sidebarContent
							send cardCollapse to .event-card
							send hide to #btnGoBackward
							set innerHTML of #currentContentText to "Linked events"
				`),
			),
		)
	}

	return sidebar
}

func EventCard(e mdb.Event, params EventCardParams) g.Node {
	var class, htmx, title, author, description, time, hyperscript, geojson, btns g.Node

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

	eventID := fmt.Sprintf("%v-%v", e.Author, e.ID)
	divID := fmt.Sprintf("%v-geojson", eventID)

	getFrom := fmt.Sprintf("/user/event/%v-%v", e.Author, e.ID)
	if params.IsSmall {
		class = gh.Class("event-card-small")
		htmx = g.Group{
			ghtmx.Get(getFrom), ghtmx.Target("this"), ghtmx.Trigger("click"), ghtmx.Swap("outerHTML"),
		}
		hyperscript = Hyperscript(`
			on load send shouldCardActivate to #btnGoBackward end
			on click
				send cardCollapse to .event-card
				call markersFromNewHide()
		`)
		description = nil
		geojson = nil
		btns = nil
	} else {
		getFrom += "?small"

		class = gh.Class("event-card")
		htmx = g.Group{
			ghtmx.Get(getFrom), ghtmx.Target("this"), ghtmx.Trigger("htmxCardCollapse"), ghtmx.Swap("outerHTML"),
		}
		hyperscript = Hyperscript(`
			on load call geoJSONStringToEventMarkers(` + `@data-geojson of #` + divID + `) end

			on click
				send cardCollapse to .event-card
			end

			on cardCollapse
				if I do not match .non-collapsable
					call markersFromEventRemove()
					call markersFromNewUnhide()
					trigger htmxCardCollapse
				end
			end

			on removeYourself
				send cardCollapse to .event-card
				remove me
		`)
		description = gh.P(g.Text(e.Description))
		geojson = gh.Div(gh.ID(divID), g.Attr("data-geojson", e.GeoJSON))

		btns = g.Group{
			gh.Button(gh.ID("btnLinksView"),
				ghtmx.Get(fmt.Sprintf("/user/event/%v-%v/links?page=%v&small", e.Author, e.ID, 0)),
				ghtmx.Trigger("fetchContent"), ghtmx.Target(".sidebar-content"), ghtmx.Swap("innerHTML"),
				Hyperscript(`
					on load
						get the closest <div/>
						if it is not #sidebarContent remove me
					end

					on click
						halt the event's bubbling
						send cardCollapse to .event-card
						send activateContent to #sidebarContent
						send pushURL(id: "`+eventID+`") to #btnGoBackward
						trigger fetchContent
				`),
				g.Text("View links"),
			),
			gh.Button(gh.ID("btnLinkThis"), gh.Class("btn-link-this"),
				Hyperscript(`
					init
						get the closest <div/>
						if it is not #sidebarContent then remove me end
					end

					on click
						halt the event's bubbling
						set :waiting to true
						add .non-collapsable to #`+eventID+`
						send btnLinkThisClicked to #btnAddEvent
					end

					on newEventFormOpen
						if :waiting is true
							set :waiting to false
							remove .non-collapsable from #`+eventID+`
							get @value of #links then call it.includes("`+eventID+`")
							if the result is false
								send addEventLink(eventID: "`+eventID+`") to #sidebarContentLinks
							end
						end
				`),
				g.Text("Link to this from new event"),
			),
			gh.Button(gh.ID("btnLinkRemove"),
				Hyperscript(`
					init
						get the closest <div/> to the closest <article/>
						if it is not #sidebarContentLinks then remove me
					end

					on click
						halt the event's bubbling
						set replacement to "`+eventID+` "
						get @value of #links then call it.replace(replacement, "") then set @value of #links to it
						send removeYourself to the closest <article/>
				`),
				g.Text("Remove this link"),
			),
		}
	}

	return gh.Article(gh.ID(eventID), class, htmx, hyperscript, title, author, time, description, geojson, btns)
}

func EventCardList(events []mdb.Event, page int, params EventCardParams) g.Node {
	if len(events) == 0 {
		return g.Raw("")
	}

	f := func(e mdb.Event) g.Node {
		return EventCard(e, params)
	}

	return g.Group{
		g.Map(events, f),
		AnchorEventLoadMore(page + 1),
	}
}

func EventCardLinksList(eventFrom mdb.Event, events []mdb.Event, page int, params EventCardParams) g.Node {
	if len(events) == 0 {
		return g.Raw("")
	}

	f := func(e mdb.Event) g.Node {
		return EventCard(e, params)
	}

	return g.Group{
		g.Map(events, f),
		AnchorEventLinkLoadMore(eventFrom, page+1),
	}
}

func EventNew() g.Node {
	return gh.Form(gh.ID("formEventNew"), ghtmx.Post("/user/event/new"), ghtmx.Target("#sidebarContent"), ghtmx.Swap("afterbegin"),
		Hyperscript(`
			on load trigger newEventFormOpen on #btnLinkThis end
			on htmx:beforeSend
				if event.detail.elt is #formEventNew
					set innerHTML of #serverResponse to ""
			end
			on htmx:afterRequest
				if event.detail.elt is #formEventNew
					if innerHTML of #serverResponse is ""
						call markersFromNewRemove() then send formEventNewClose to #sidebarControls
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
		gh.Input(gh.Type("hidden"), gh.Name("links"), gh.ID("links"), gh.Value("")),
		gh.Button(gh.Type("button"),
			Hyperscript(`
				on click
					halt the event's bubbling
					call markerPlace()
					send cardCollapse to .event-card
			`),
			g.Text("Add marker"),
		),
		gh.Button(gh.Type("button"),
			Hyperscript(`
				on click
					halt the event's bubbling
					call markerRemove()
					send cardCollapse to .event-card
			`),
			g.Text("Remove marker"),
		),
		gh.Button(gh.ID("btnEventLinksView"),
			Hyperscript(`
				on click
					halt the event
					if my innerHTML is equal to "View added links to this event"
						set my innerHTML to "Go back to events"
						send activateContent to #sidebarContentLinks
					else
						set my innerHTML to "View added links to this event"
						send activateContent to #sidebarContent
					end
				end

				on reset
					set my innerHTML to "View added links to this event"
					send cardCollapse to .event-card
			`),
			g.Text("View added links to this event"),
		),
		gh.Button(gh.Type("submit"),
			Hyperscript(`
				on click
					call markersFromNewToGeoJSONString() then put the result into @value of #geojson
					send activateContent to #sidebarContent
			`),
			g.Text("Send"),
		),
		gh.Div(gh.ID("serverResponse")),
	)
}

func EventNewError(id, message string) g.Node {
	return g.Group{
		gh.Div(gh.Class("server-response"), gh.ID(id), ghtmx.SwapOOB("outerHTML"), g.Text(message)),
	}
}

func AnchorEventLoadMore(nextPage int) g.Node {
	url := fmt.Sprintf("/user/events?page=%v&small", nextPage)
	nextPageString := fmt.Sprintf("%v", nextPage)
	return gh.Article(ghtmx.Get(url), ghtmx.Trigger("intersect once"), ghtmx.Target("this"), ghtmx.Swap("afterend"),
		Hyperscript(`
			on htmx:beforeSend
				if event.detail.elt is me
					send currentPage(url: @hx-get + "&upToPage", page: `+nextPageString+`) to #btnGoBackward
		`),
	)
}

func AnchorEventLinkLoadMore(e mdb.Event, nextPage int) g.Node {
	url := fmt.Sprintf("/user/event/%v-%v/links?page=%v&small", e.Author, e.ID, nextPage)
	nextPageString := fmt.Sprintf("%v", nextPage)
	return gh.Article(ghtmx.Get(url), ghtmx.Trigger("intersect once"), ghtmx.Target("this"), ghtmx.Swap("afterend"),
		Hyperscript(`
			on htmx:beforeSend
				if event.detail.elt is me
					send currentPage(url: @hx-get + "&upToPage", page: `+nextPageString+`) to #btnGoBackward
		`),
	)
}

package pages

import (
	"strconv"

	g "maragu.dev/gomponents"
	ghtmx "maragu.dev/gomponents-htmx"
	gc "maragu.dev/gomponents/components"
	gh "maragu.dev/gomponents/html"

	mdb "github.com/liondandelion/metla/internal/db"
	mc "github.com/liondandelion/metla/internal/html/components"
)

type PageProperties struct {
	Title       string
	Description string
}

func page(props PageProperties, userSession mdb.UserSessionData, children ...g.Node) g.Node {
	return gc.HTML5(
		gc.HTML5Props{
			Title:       props.Title,
			Description: props.Description,
			Language:    "en",
			Head: []g.Node{
				gh.Link(gh.Rel("icon"), gh.Type("image/png"), g.Attr("sizes", "32x32"), gh.Href("/assets/img/metla-32.png")),
				gh.Link(gh.Rel("icon"), gh.Type("image/png"), g.Attr("sizes", "16x16"), gh.Href("/assets/img/metla-16.png")),
				gh.Link(gh.Rel("stylesheet"), gh.Type("text/css"), gh.Href("/assets/css/style.css")),
				gh.Script(gh.Src("/assets/js/third_party/htmx.js")),
				gh.Script(gh.Src("/assets/js/third_party/_hyperscript.js")),
				mc.Navbar(userSession.Username, userSession.IsAuthenticated, userSession.IsAdmin),
			},
			Body: []g.Node{
				gh.Main(gh.Class("grid-main"), g.Group(children)),
			},
		},
	)
}

func Map(userSession mdb.UserSessionData) g.Node {
	var sidebar g.Node

	if !userSession.IsAuthenticated {
		sidebar = gh.Aside(gh.ID("sidebar"), gh.Class("sidebar"),
			gh.P(g.Text("There is nothing to show here yet. Please "),
				gh.A(gh.Href("/register"), gh.U(g.Text("register"))),
				g.Text(" or "),
				gh.A(gh.Href("/login"), gh.U(g.Text("login"))),
				g.Text(" to see more."),
			),
		)
	} else {
		sidebar = gh.Aside(gh.ID("sidebar"), gh.Class("sidebar"),
			gh.Div(gh.Class("sidebar-controls"),
				gh.Button(gh.ID("btnAddEvent"), g.Text("Add event"),
					ghtmx.Trigger("click"), ghtmx.Get("/user/event/new"),
				),
			),
			gh.Div(gh.Class("sidebar-content"),
				gh.Article(ghtmx.Trigger("intersect once"), ghtmx.Get("/user/event?page=0"), ghtmx.Swap("outerHTML")),
			),
		)
		// sidebar = gh.Aside(gh.Class("sidebar"),
		// 	gh.Button(g.Text("Add marker"),
		// 		mc.Hyperscript(`
		// 			on click call placeMarker()
		// 		`),
		// 	),
		// 	gh.Button(g.Text("Remove marker"),
		// 		mc.Hyperscript(`
		// 			on click call removeMarker()
		// 		`),
		// 	),
		// 	gh.Button(g.Text("To geojson"),
		// 		mc.Hyperscript(`
		// 			on click call markersToGeoJSON()
		// 		`),
		// 	),
		// 	gh.P(g.Text("Sidebar! AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")),
		// 	gh.P(g.Text("Sidebar! AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")),
		// )
	}

	return page(
		PageProperties{Title: "Map"},
		userSession,
		gh.Script(gh.Src("/assets/js/third_party/maplibre-gl.js")),
		gh.Script(gh.Src("/assets/js/third_party/pmtiles.js")),
		gh.Link(gh.Rel("stylesheet"), gh.Type("text/css"), gh.Href("/assets/css/third_party/maplibre-gl.css")),
		gh.Div(gh.Class("map-div"),
			sidebar,
			gh.Div(gh.ID("map"), gh.Class("map"),
				mc.Hyperscript(`
					on mouseleave call onMouseLeftMap()
				`),
				gh.Div(gh.ID("zoom"),
					g.Text("Zoom: "),
					gh.Span(gh.ID("zoomNum")),
				),
				gh.Pre(gh.ID("features")),
			),
		),
		gh.Script(gh.Src("/assets/js/map.js")),
	)
}

func Register(userSession mdb.UserSessionData) g.Node {
	return page(
		PageProperties{Title: "Register"},
		userSession,
		gh.Form(gh.ID("registerForm"),
			gh.Label(gh.For("username"), g.Text("Enter your username: ")),
			gh.Input(gh.Type("text"), gh.Name("username"), gh.Required()),
			gh.Label(gh.For("password"), g.Text("Enter your password: ")),
			gh.Input(gh.Type("password"), gh.Name("password"), gh.Required()),
			gh.Label(gh.For("confirm"), g.Text("Confirm password: ")),
			gh.Input(gh.Type("password"), gh.Name("confirm"), gh.Required()),
			gh.Input(gh.Type("submit"), gh.Value("Register"), ghtmx.Post("/register"), ghtmx.Target("#serverResponse"), ghtmx.Swap("outerHTML")),
			gh.Div(gh.ID("serverResponse")),
		),
	)
}

func Login(userSession mdb.UserSessionData) g.Node {
	return page(
		PageProperties{Title: "Login"},
		userSession,
		gh.Form(gh.ID("loginForm"),
			mc.Hyperscript(`
				on htmx:afterRequest
					if #otpForm is not empty remove me
			`),
			gh.Label(gh.For("username"), g.Text("Enter your username: ")),
			gh.Input(gh.Type("text"), gh.Name("username"), gh.Required()),
			gh.Label(gh.For("passowrd"), g.Text("Enter your password: ")),
			gh.Input(gh.Type("password"), gh.Name("password"), gh.Required()),
			gh.Input(gh.Type("submit"), gh.Value("Login"), ghtmx.Post("/login"), ghtmx.Target("#serverResponse"), ghtmx.Swap("outerHTML")),
			gh.Div(gh.ID("serverResponse")),
		),
	)
}

func User(userSession mdb.UserSessionData) g.Node {
	return page(
		PageProperties{Title: "User"},
		userSession,
		gh.Nav(gh.Class("user-profile"),
			gh.Ul(
				g.If(userSession.IsAuthenticated,
					g.Group{
						gh.Li(
							gh.A(gh.Href("/user/password"), g.Text("Change password")),
						),
						g.If(userSession.IsOTPEnabled,
							gh.Li(
								gh.A(gh.Href("/user/otp/disable"), g.Text("Disable OTP")),
							),
						),
						g.If(!userSession.IsOTPEnabled,
							gh.Li(
								gh.A(gh.Href("/user/otp/enable"), g.Text("Enable OTP")),
							),
						),
					},
				),
			),
		),
	)
}

func PasswordChange(userSession mdb.UserSessionData) g.Node {
	return page(
		PageProperties{Title: "Change password"},
		userSession,
		gh.Form(gh.ID("passwordChangeForm"),
			mc.Hyperscript(`
				on htmx:afterRequest
					if #otpForm is not empty remove me
			`),
			gh.Label(gh.For("password"), g.Text("Old password: ")),
			gh.Input(gh.Type("password"), gh.Name("oldPassword"), gh.Required()),
			gh.Label(gh.For("password"), g.Text("New password: ")),
			gh.Input(gh.Type("password"), gh.Name("newPassword"), gh.Required()),
			gh.Label(gh.For("confirm"), g.Text("Confirm new password: ")),
			gh.Input(gh.Type("password"), gh.Name("confirm"), gh.Required()),
			gh.Input(gh.Type("submit"), gh.Value("Change"), ghtmx.Post("/user/password"), ghtmx.Target("#serverResponse"), ghtmx.Swap("outerHTML")),
			gh.Div(gh.ID("serverResponse")),
		),
	)
}

func UserTable(userSession mdb.UserSessionData, users []mdb.User) g.Node {
	return page(
		PageProperties{Title: "UserTable"},
		userSession,
		gh.Table(
			gh.THead(
				gh.Tr(
					gh.Th(gh.Scope("col"), g.Text("Username")),
					gh.Th(gh.Scope("col"), g.Text("Password hash")),
					gh.Th(gh.Scope("col"), g.Text("Is admin")),
				),
			),
			gh.TBody(
				g.Map(users, func(user mdb.User) g.Node {
					return gh.Tr(
						gh.Td(g.Text(user.Username)),
						gh.Td(g.Text(string(user.PasswordHash))),
						gh.Td(g.Text(strconv.FormatBool(user.IsAdmin))),
					)
				}),
			),
		),
	)
}

func OTPEnable(userSession mdb.UserSessionData, service, username, secret, image string) g.Node {
	return page(
		PageProperties{Title: "Change password"},
		userSession,
		gh.H1(g.Text("For manual enrollment use this information:")),
		gh.P(g.Text("Service: "+service)),
		gh.P(g.Text("Username: "+username)),
		gh.P(g.Text("Secret: "+secret)),
		gh.Img(gh.Src("data:image/png;base64, "+image), gh.Style("width: 200px; height: 200px;"), gh.Alt("QR code for OTP enrollment")),
		gh.P(g.Text("After enrollment, please enter the code below")),
		mc.FormOTP("/user/otp/enable"),
	)
}

func OTPDisable(userSession mdb.UserSessionData) g.Node {
	return page(
		PageProperties{Title: "Disable OTP"},
		userSession,
		mc.FormOTP("/user/otp/disable"),
	)
}

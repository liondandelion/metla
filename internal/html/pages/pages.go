package pages

import (
	"strconv"

	g "maragu.dev/gomponents"
	ghtmx "maragu.dev/gomponents-htmx"
	gc "maragu.dev/gomponents/components"
	gh "maragu.dev/gomponents/html"

	mdb "github.com/liondandelion/metla/internal/db"
	mc "github.com/liondandelion/metla/internal/html/components"
	mhtmx "github.com/liondandelion/metla/internal/html/htmx"
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
				gh.Main(gh.Class("grid-main fullsize"), g.Group(children)),
			},
		},
	)
}

func Map(userSession mdb.UserSessionData) g.Node {
	return page(
		PageProperties{Title: "Map"},
		userSession,
		g.Group{
			gh.Script(gh.Src("/assets/js/third_party/maplibre-gl.js")),
			gh.Script(gh.Src("/assets/js/third_party/pmtiles.js")),
			gh.Link(gh.Rel("stylesheet"), gh.Type("text/css"), gh.Href("/assets/css/third_party/maplibre-gl.css")),
			gh.StyleEl(g.Text("#features { position: absolute; top: 50%; right: 0; bottom: 0; width: 25%; overflow: auto; background: rgba(255, 255, 255, 0.2); }")),
			gh.Div(gh.Class("grid-map fullsize"),
				gh.Aside(gh.Class("grid-map-sidebar sidebar"),
					g.Group{
						gh.P(g.Text("Sidebar! AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")),
						gh.P(g.Text("Sidebar! AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")),
					},
				),
				gh.Div(gh.ID("map"), gh.Class("grid-map-map fullsize"), gh.Style("z-index: 1;"),
					gh.Div(gh.ID("zoom"), gh.Style("z-index: 2; position: absolute; top: 10px; left: 10px;"),
						g.Text("Zoom: "),
						gh.Span(gh.ID("zoomNum")),
					),
					gh.Pre(gh.ID("features"), gh.Style("z-index: 2;")),
				),
			),
			gh.Script(gh.Src("/assets/js/map.js")),
		},
	)
}

func Register(userSession mdb.UserSessionData) g.Node {
	return page(
		PageProperties{Title: "Register"},
		userSession,
		g.Group{
			gh.Form(gh.ID("registerForm"), gh.Class("form"),
				gh.Div(gh.Class("form"),
					gh.Label(gh.For("username"), g.Text("Enter your username: ")),
					gh.Input(gh.Type("text"), gh.Name("username"), gh.Required()),
				),
				gh.Div(gh.Class("form"),
					gh.Label(gh.For("password"), g.Text("Enter your password: ")),
					gh.Input(gh.Type("password"), gh.Name("password"), gh.Required()),
				),
				gh.Div(gh.Class("form"),
					gh.Label(gh.For("confirm"), g.Text("Confirm password: ")),
					gh.Input(gh.Type("password"), gh.Name("confirm"), gh.Required()),
				),
				gh.Div(gh.Class("form"),
					gh.Input(gh.Type("submit"), gh.Value("Register"), ghtmx.Post("/register"), ghtmx.Target("#serverResponse"), ghtmx.Swap("outerHTML")),
				),
			),
			gh.Div(gh.ID("serverResponse")),
		},
	)
}

func Login(userSession mdb.UserSessionData) g.Node {
	return page(
		PageProperties{Title: "Login"},
		userSession,
		g.Group{
			gh.Form(gh.ID("loginForm"), gh.Class("form"),
				mc.Hyperscript(`
					on htmx:afterRequest
						if #otpForm is not empty remove me
				`),
				gh.Div(gh.Class("form"),
					gh.Label(gh.For("username"), g.Text("Enter your username: ")),
					gh.Input(gh.Type("text"), gh.Name("username"), gh.Required()),
				),
				gh.Div(gh.Class("form"),
					gh.Label(gh.For("passowrd"), g.Text("Enter your password: ")),
					gh.Input(gh.Type("password"), gh.Name("password"), gh.Required()),
				),
				gh.Div(gh.Class("form"),
					gh.Input(gh.Type("submit"), gh.Value("Login"), ghtmx.Post("/login"), ghtmx.Target("#serverResponse"), ghtmx.Swap("outerHTML")),
				),
			),
			gh.Div(gh.ID("serverResponse")),
		},
	)
}

func User(userSession mdb.UserSessionData) g.Node {
	return page(
		PageProperties{Title: "User"},
		userSession,
		g.Group{
			gh.Nav(
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
		},
	)
}

func PasswordChange(userSession mdb.UserSessionData) g.Node {
	return page(
		PageProperties{Title: "Change password"},
		userSession,
		g.Group{
			gh.Form(gh.ID("passwordChangeForm"), gh.Class("form"),
				mc.Hyperscript(`
					on htmx:afterRequest
						if #otpForm is not empty remove me
				`),
				gh.Div(gh.Class("form"),
					gh.Label(gh.For("password"), g.Text("Old password: ")),
					gh.Input(gh.Type("password"), gh.Name("oldPassword"), gh.Required()),
				),
				gh.Div(gh.Class("form"),
					gh.Label(gh.For("password"), g.Text("New password: ")),
					gh.Input(gh.Type("password"), gh.Name("newPassword"), gh.Required()),
				),
				gh.Div(gh.Class("form"),
					gh.Label(gh.For("confirm"), g.Text("Confirm new password: ")),
					gh.Input(gh.Type("password"), gh.Name("confirm"), gh.Required()),
				),
				gh.Div(gh.Class("form"),
					gh.Input(gh.Type("submit"), gh.Value("Change"), ghtmx.Post("/user/password"), ghtmx.Target("#serverResponse"), ghtmx.Swap("outerHTML")),
				),
			),
			gh.Div(gh.ID("serverResponse")),
		},
	)
}

func UserTable(userSession mdb.UserSessionData, users []mdb.User) g.Node {
	return page(
		PageProperties{Title: "UserTable"},
		userSession,
		g.Group{
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
		},
	)
}

func OTPEnable(userSession mdb.UserSessionData, service, username, secret, image string) g.Node {
	return page(
		PageProperties{Title: "Change password"},
		userSession,
		g.Group{
			gh.H1(g.Text("For manual enrollment use this information:")),
			gh.P(g.Text("Service: " + service)),
			gh.P(g.Text("Username: " + username)),
			gh.P(g.Text("Secret: " + secret)),
			gh.Img(gh.Src("data:image/png;base64, "+image), gh.Style("width: 200px; height: 200px;"), gh.Alt("QR code for OTP enrollment")),
			gh.P(g.Text("After enrollment, please enter the code below")),
			mhtmx.FormOTP("/user/otp/enable"),
			gh.Div(gh.ID("serverResponse")),
		},
	)
}

func OTPDisable(userSession mdb.UserSessionData) g.Node {
	return page(
		PageProperties{Title: "Disable OTP"},
		userSession,
		g.Group{
			mhtmx.FormOTP("/user/otp/disable"),
			gh.Div(gh.ID("serverResponse")),
		},
	)
}

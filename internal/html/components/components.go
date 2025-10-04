package components

import (
	"strings"
	"unicode"

	g "maragu.dev/gomponents"
	gh "maragu.dev/gomponents/html"
)

func Hyperscript(script string) g.Node {
	trimmed := strings.TrimLeftFunc(script, unicode.IsSpace)
	trimmed = strings.TrimRightFunc(trimmed, unicode.IsSpace)
	return g.Attr("_", trimmed)
}

func Navbar(username string, isAuthenticated, isAdmin bool) g.Node {
	return gh.Header(gh.Class("grid-navbar header"),
		gh.Nav(gh.Class("navbar"),
			gh.Ul(gh.Class("navbar-left-side"),
				gh.Li(gh.Class("navbar-list-item"),
					gh.A(gh.Href("/"), gh.Class("left"), g.Text("Metla")),
				),
			),
			gh.Ul(gh.Class("navbar-right-side"),
				g.If(isAuthenticated,
					g.Group{
						gh.Li(gh.Class("navbar-list-item"),
							gh.A(gh.Href("/user"), g.Text(username)),
						),
						g.If(isAdmin,
							gh.Li(gh.Class("navbar-list-item"),
								gh.A(gh.Href("/userstable"), g.Text("Users")),
							),
						),
						gh.Li(gh.Class("navbar-list-item"),
							gh.A(gh.Href("/logout"), g.Text("Logout")),
						),
					},
				),
				g.If(!isAuthenticated,
					g.Group{
						gh.Li(gh.Class("navbar-list-item"),
							gh.A(gh.Href("/register"), g.Text("Register")),
						),
						gh.Li(gh.Class("navbar-list-item"),
							gh.A(gh.Href("/login"), g.Text("Login")),
						),
					},
				),
			),
		),
	)
}

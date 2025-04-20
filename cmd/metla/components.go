package main

import (
	g "maragu.dev/gomponents"
	h "maragu.dev/gomponents/html"
	c "maragu.dev/gomponents/components"
)

func Page(title string, children ...g.Node) g.Node {
	return c.HTML5(c.HTML5Props {
		Title: title,
		Language: "en",
		Body: []g.Node {
			g.Group(children),
		},
	})
}

func LinkHome() g.Node {
	return h.A(h.Href("/"), g.Text("Back home"))
}

func RootPage() g.Node {
	return c.HTML5(c.HTML5Props {
		Title: "Index",
		Language: "en",
		Body: []g.Node {
			h.P(g.Text("Website's map")),
			h.Ul(
				h.Li(h.A(h.Href("/register"), g.Text("Register"))),
				h.Li(h.A(h.Href("/debug_users"), g.Text("Debug users table"))),
			),
		},
	})
}

func RegisterPage() g.Node {
	return c.HTML5(c.HTML5Props {
		Title: "Register",
		Language: "en",
		Head: []g.Node {
			h.Link(h.Rel("stylesheet"), h.Type("text/css"), h.Href("/static/form-demo.css")),
		},
		Body: []g.Node {
			h.Form(h.Action("/register"), h.Method("post"), h.Class("form-example"),
				h.Div(h.Class("form-example"),
					h.Label(h.For("email"), g.Text("Enter your email: ")),
					h.Input(h.Type("email"), h.Name("email"), h.ID("email"), h.Required()),
				),
				h.Div(h.Class("form-example"),
					h.Label(h.For("username"), g.Text("Enter your username: ")),
					h.Input(h.Type("text"), h.Name("username"), h.ID("username"), h.Required()),
				),
				h.Div(h.Class("form-example"),
					h.Label(h.For("password"), g.Text("Enter your password: ")),
					h.Input(h.Type("password"), h.Name("password"), h.ID("password"), h.Required()),
				),
				h.Div(h.Class("form-example"),
					h.Input(h.Type("submit"), h.Value("Register")),
				),
			),
			LinkHome(),
		},
	})
}

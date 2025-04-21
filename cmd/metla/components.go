package main

import (
	g "maragu.dev/gomponents"
	c "maragu.dev/gomponents/components"
	h "maragu.dev/gomponents/html"
)

func Page(title string, children ...g.Node) g.Node {
	return c.HTML5(c.HTML5Props{
		Title:    title,
		Language: "en",
		Body: []g.Node{
			g.Group(children),
		},
	})
}

func LinkHome() g.Node {
	return h.A(h.Href("/"), g.Text("Back home"))
}

func HomePage() g.Node {
	return c.HTML5(c.HTML5Props{
		Title:    "Index",
		Language: "en",
		Body: []g.Node{
			h.P(g.Text("Website's map")),
			h.Ul(
				h.Li(h.A(h.Href("/register"), g.Text("Register"))),
				h.Li(h.A(h.Href("/userstable"), g.Text("Print users table"))),
			),
		},
	})
}

func RegisterPage() g.Node {
	return c.HTML5(c.HTML5Props{
		Title:    "Register",
		Language: "en",
		Head: []g.Node{
			h.Link(h.Rel("stylesheet"), h.Type("text/css"), h.Href("/static/form-demo.css")),
		},
		Body: []g.Node{
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

func UsersTablePage(users []User) g.Node {
	forloop := func(users []User) []g.Node {
		list := make([]g.Node, 0, 10)
		for _, user := range users {
			node := h.Tr(
				h.Th(g.Attr("scope", "row"), g.Text(user.Email)),
				h.Td(g.Text(user.Username)),
				h.Td(g.Text(user.Password_hash)),
			)
			list = append(list, node)
		}
		return list
	}

	return c.HTML5(c.HTML5Props{
		Title:    "Userdebug",
		Language: "en",
		Body: []g.Node{
			h.Table(
				h.THead(
					h.Tr(
						h.Th(g.Attr("scope", "col"), g.Text("Email")),
						h.Th(g.Attr("scope", "col"), g.Text("Username")),
						h.Th(g.Attr("scope", "col"), g.Text("Password hash")),
					),
				),
				h.TBody(
					forloop(users)...,
				),
			),
			h.Br(),
			LinkHome(),
		},
	})
}

package htmx

import (
	g "maragu.dev/gomponents"
	ghtmx "maragu.dev/gomponents-htmx"
	gh "maragu.dev/gomponents/html"

	mc "github.com/liondandelion/metla/internal/html/components"
)

func Error(id, message string) g.Node {
	return gh.Div(gh.ID(id), g.Text(message))
}

func FormOTP(postTo string) g.Node {
	return g.Group{
		gh.Form(gh.ID("otpForm"),
			gh.Label(gh.For("otpCode"), g.Text("OTP code: ")),
			gh.Input(gh.Type("text"), gh.Name("otpCode"), gh.ID("otpCode"), gh.Required(), gh.AutoFocus(),
				mc.Hyperscript(`
					on load put '' into me
				`),
			),
			gh.Input(gh.Type("submit"), gh.Value("Send"), ghtmx.Post(postTo), ghtmx.Target("#serverResponse"), ghtmx.Swap("outerHTML"),
				mc.Hyperscript(`
					on click wait 100ms then set value of #otpCode to ''
				`),
			),
		),
		gh.Div(gh.ID("serverResponse")),
	}
}

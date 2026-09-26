import html

def render_greeting(name):
    return "<b>Hello " + html.escape(name) + "</b>"

About
-----

Have you ever pen-tested a .NET app and found that it has all sorts of ugly parameter names
(i.e. ctl0$blah$foo$VeryLongLine)? Sometimes these parameters can be pages long (i.e. __VIEWSTATE). Have you felt
like killing yourself because you can't even read the whole parameter name and see what it's corresponding value is in
your small screen at a client site? Don't you wish you could only focus on the meat of the request?

Well cry no more! This tool is about bringing awesome back to pentesting .NET apps. It makes requests like this:

```http
POST /Default.aspx HTTP/1.1
Host: annoying-web-app
Referer: https://annoying-web-app/Default.aspx
Cookie: ASP.NET_SessionId=zprxqvwll4yoi0gbeactgzdd
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 1903

__VIEWSTATE=%2oiAIHfiohsdoigjKLASgjghajklgjSDGsjdglSDJg9SDJGsdgjSGJDDSasdfja9sdjfasdfja0sdfjasd53j5235923nf9ja9fsdjfajsD
... [1000 lines later] ...
&ctl00%24ctl00%24InnerContentPlaceHolder%24Element_42%24ctl00%24FrmLogin%24TxtUsername_internal=username&ctl00%24ctl00%2
4InnerContentPlaceHolder%24Element_42%24ctl00%24FrmLogin%24TxtPassword_internal=password&ctl00%24ctl00%24InnerContentPla
ceHolder%24Element_42%24ctl00%24BtnLogin=Login
```

Look like this:

```http
POST /Default.aspx HTTP/1.1
Host: annoying-web-app
Referer: https://annoying-web-app/Default.aspx
Cookie: ASP.NET_SessionId=zprxqvwll4yoi0gbeactgzdd
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 1903
X-dotNet-Beautifier: 259; DO-NOT-REMOVE

__VIEWSTATE=<snipped out for sanity>&TxtUsername_internal=username&TxtPassword_internal=password&BtnLogin=Login```

All **without** compromising the integrity of the outgoing message so you can alter the values of the parameters you
want to target *without losing your mind*! Better yet, you can send "beautified" messages to other tools within Burp and
the outgoing messages will get automatically transformed back into what the web app expects from us.

**WAWAWEWA!**


Requirements
------------

You'll need the following to get started:
- the standalone version of Jython available at http://www.jython.org/downloads.html.
- the latest version of BurpSuite versions 1.6 or later.
- a positive attitude!

Help!
-----

This is still a work in progress so their may be a few bugs I haven't hammered out.
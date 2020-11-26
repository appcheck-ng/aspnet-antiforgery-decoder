# ASP.NET Antiforgery Cookie Name Discloses Virtual Application Path

Applications written ASP.NET can take advantage of the antiforgery middleware to prevent Cross Site Request Forgery
attacks. 

When testing ASP.NET application with antiforgery enabled, it is not uncommon to observe cookies with a name like
__RequestVerificaitonToken_L2hlbHBkZXNr0. The default cookie and parameter name is __RequestVerificationToken, the
additional section of the name is an encoded representation of the virtual application path, which can trivially
decoded.

On its own, knowledge of the virtual application path is of limited use and may also form the first part of the URL
depending on the environment. However, in some cases it may help to inform or target further attacks against the
application.

This utility expects a cookie name and returns the decoded virtual application path.

# Example Usage
## Decode cookie
```
$ python3 decode_aspnet_antiforgery_cookie_name.py -c __RequestVerificaitonToken_L2hlbHBkZXNr0
__RequestVerificaitonToken_L2hlbHBkZXNr0 -> /helpdesk
```
## Help output
```
$ python aspnet_antiforgery_decoder.py --help
usage: aspnet_antiforgery_decoder.py [-h] -c COOKIE

[
[   /_\  _ __  _ __   / __\ |__   ___  ___| |
[  //_\\| '_ \| '_ \ / /  | '_ \ / _ \/ __| |/ /
[ /  _  \ |_) | |_) / /___| | | |  __/ (__|   <
[ \_/ \_/ .__/| .__/\____/|_| |_|\___|\___|_|\_\
[       |_|   |_|              AppCheck Ltd 2020
[
[ Decode ASP.NET Antiforgery Cookie Name

optional arguments:
  -h, --help            show this help message and exit
  -c COOKIE, --cookie COOKIE
                        ASP.NET Antiforgery Cookie Name
```


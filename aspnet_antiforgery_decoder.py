#!/usr/bin/env python3
"""
Extract and decode the ASP.NET Virtual Application Path from an Antiforgery cookie name.
"""
import typing as _t
import argparse
import sys

from base64 import b64decode

__author__ = "Oliver Morton (GrimHacker)"
__copyright__ = "Copyright 2020, AppCheck-NG Ltd"
__license__ = "MIT License"
__version__ = "1.0"
__email__ = "info[at]appcheck-ng.com"


def decode_aspnet_antiforgery_cookie_apppath(encoded_apppath):
    # type: (str) -> str
    """Return the decoded appPath from encoded_apppath."""
    # Microsoft are using a custom "URL Safe" Base64 encoding method.
    # The padding is removed and replaced with an integer representing how many "=" are required (most of the time)
    # the "+" is transfored to "-", and "/" to "_".
    # https://referencesource.microsoft.com/#System.Web/Util/HttpEncoder.cs,872
    # I've observed that the padding count is sometimes missing...
    encoded = None
    if encoded_apppath[-1].isdigit():
        # If there is an integer at the end, check if it is the pad length
        given_pad_len = int(encoded_apppath[-1])
        calculated_pad_len = (4 - len(encoded_apppath[:-1])) % 4
        if given_pad_len == calculated_pad_len or (calculated_pad_len == 0 and given_pad_len == 4):
            # Looks like the given integer is the pad length, remove the integer and add the padding.
            encoded = encoded_apppath[:-1] + ("=" * calculated_pad_len)

    if encoded is None:
        # Looks like padding wasn't included.
        # Calculate the padding and append it.
        calculated_pad_len = (4 - len(encoded_apppath)) % 4
        encoded = encoded_apppath + ("=" * calculated_pad_len)

    encoded = encoded.replace('-', '+').replace('/', '_')
    return b64decode(encoded).decode("utf-8")


def extract_encoded_apppath(cookie):
    # type: (str) -> _t.Optional[str]
    """Extract the encoded apppath from cookie if present."""
    _, sep, encoded_apppath = cookie.rpartition('_')
    if sep and encoded_apppath.startswith('L'):
        return encoded_apppath
    else:
        raise ValueError("'{}' does not appear to contain an encoded appPath".format(cookie))


def main():
    # type: () -> None
    """Parse commandline and decode given cookie name."""
    banner = r"""
[
[   /_\  _ __  _ __   / __\ |__   ___  ___| |
[  //_\\| '_ \| '_ \ / /  | '_ \ / _ \/ __| |/ /
[ /  _  \ |_) | |_) / /___| | | |  __/ (__|   <
[ \_/ \_/ .__/| .__/\____/|_| |_|\___|\___|_|\_\
[       |_|   |_|              AppCheck Ltd 2020
[
[ Decode ASP.NET Antiforgery Cookie Name
"""
    parser = argparse.ArgumentParser(description=banner, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-c", "--cookie", help="ASP.NET Antiforgery Cookie Name", required=True)
    args = parser.parse_args()
    cookie = args.cookie
    encoded_apppath = extract_encoded_apppath(cookie)
    apppath = decode_aspnet_antiforgery_cookie_apppath(encoded_apppath)
    if not apppath.startswith("/"):
        print("WARNING: does not appear to be a valid appPath.")
    print("{} -> {}\n".format(cookie, apppath))


if __name__ == "__main__":
    main()

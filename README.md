# go-ipdata
[![License](https://img.shields.io/github/license/theckman/go-ipdata.svg)](https://github.com/theckman/go-ipdata/blob/master/LICENSE)
[![GoDoc](https://img.shields.io/badge/godoc-reference-blue.svg?style=flat)](https://godoc.org/github.com/theckman/go-ipdata)
[![Latest Git Tag](https://img.shields.io/github/tag/theckman/go-ipdata.svg)](https://github.com/theckman/go-ipdata/releases)
[![Travis master Build Status](https://img.shields.io/travis/theckman/go-ipdata/master.svg?label=TravisCI)](https://travis-ci.org/theckman/go-ipdata/branches)

Package ipdata is a client for the https://ipdata.co API. It provides functions
for looking up data, as well as parsing the data in a programmatic way. The
simplest usage is to build a new client and then use the `Lookup` method.

## License
This code is released under the MIT License. Please see the
[LICENSE](https://github.com/theckman/go-ipdata/blob/master/LICENSE) for the
full content of the license.

## Contributing
If you'd like to contribute to this project, I welcome any pull requests against
this repo. The only ask is that a GitHub issue be opened detailing the desired
functionality before making any pull requests.

## Usage
The service provided by `ipdata` can be used anonymously or with an API key. The
anonymous usage is subject to rate limits. If you are using the anonymous
service, providing an empty string as an API key is how you inform the API
client to issue anonymous requests.

```Go
import "github.com/theckman/go-ipdata"

ipd := ipdata.NewClient("")

data, err := ipd.Lookup("8.8.8.8")
if err != nil {
	// handle error
}

fmt.Printf("%s (%s)\n", data.IP, data.ASN)
```

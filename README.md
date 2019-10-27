# go-ipdata
[![License](https://img.shields.io/github/license/theckman/go-ipdata.svg)](https://github.com/theckman/go-ipdata/blob/master/LICENSE)
[![GoDoc](https://img.shields.io/badge/godoc-reference-blue.svg?style=flat)](https://godoc.org/github.com/theckman/go-ipdata)
[![Latest Git Tag](https://img.shields.io/github/tag/theckman/go-ipdata.svg)](https://github.com/theckman/go-ipdata/releases)
[![Travis master Build Status](https://img.shields.io/travis/theckman/go-ipdata/master.svg?label=TravisCI)](https://travis-ci.org/theckman/go-ipdata/branches)
[![Go Cover Test Coverage](https://gocover.io/_badge/github.com/theckman/go-ipdata?v0)](https://gocover.io/github.com/theckman/go-ipdata)
[![Go Report Card](https://goreportcard.com/badge/github.com/theckman/go-ipdata)](https://goreportcard.com/report/github.com/theckman/go-ipdata)

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
The service provided by `ipdata` requires an API key before making API calls.
Attempts to create a client without one will fail, as would attempts to contact
the API. You can get an API key from https://ipdata.co/.

Here is a simple example of using the library:

```Go
import "github.com/theckman/go-ipdata"

ipd := ipdata.NewClient("EXAMPLE_API_KEY")

data, err := ipd.Lookup("8.8.8.8")
if err != nil {
	// handle error
}

fmt.Printf("%s (%s)\n", data.IP, data.ASN)
```

Errors returned from the lookup function calls may be of type `Error`, which
includes the message from the API and the HTTP status code. The `Error()` method
on this type only returns the message and not the status code. To maintain
compatibility with Go 1.12.x, this is still using github.com/pkg/errors for
error management:

```Go
import "github.com/pkg/errors"

data, err := ipd.Lookup("8.8.8.8")
if err != nil {
	// do a type assertion on the error
	rerr, ok := errors.Cause(err).(ipdata.Error)

    if !ok {
    	// this wasn't a failure from rate limiting
    }
    
    fmt.Println("%d: %s", rerr.Code(), rerr.Int())
}
```

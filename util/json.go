// Copyright (c) 2017-2019 The UtopiaCoinOrg developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package util

import (
	"encoding/json"
	"github.com/gorilla/schema"
	"io"
	"net/http"
)

func RespondWithError(w http.ResponseWriter, code int, message string) {
	RespondWithJSON(w, code, map[string]string{"error": message})
}

func RespondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	response, _ := json.Marshal(payload)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(response)
}

func RespondWithCopy(w http.ResponseWriter, code int, contentType string, body []byte) error {
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(code)
	_, err := w.Write(body)
	return err
}

// GetErrorFromJSON returns the error that is embedded in a JSON reply.
func GetErrorFromJSON(r io.Reader) (interface{}, error) {
	var e interface{}
	decoder := json.NewDecoder(r)
	if err := decoder.Decode(&e); err != nil {
		return nil, err
	}
	return e, nil
}

// ParseGetParams parses the query params from the GET request into
// a struct. This method requires the struct type to be defined
// with `schema` tags.
func ParseGetParams(r *http.Request, dst interface{}) error {
	err := r.ParseForm()
	if err != nil {
		return err
	}

	return schema.NewDecoder().Decode(dst, r.Form)
}

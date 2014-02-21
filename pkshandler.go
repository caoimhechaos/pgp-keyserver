/**
 * Copyright (c) 2014, Caoimhe Chaos <caoimhechaos@protonmail.com>.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice, this
 *   list of conditions and the following disclaimer in the documentation and/or
 *  other materials provided with the distribution.
 *
 * * Neither the name of Ancient Solutions nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package main

import (
	"expvar"
	"log"
	"net/http"
	"strings"
)

var pksreqs *expvar.Int = expvar.NewInt("num-pks-reqs")
var pksunknownreqs *expvar.Int = expvar.NewInt("num-pks-unknown-reqs")
var pksaddreqs *expvar.Int = expvar.NewInt("num-pks-add-reqs")
var pkslookupreqs *expvar.Int = expvar.NewInt("num-pks-lookup-reqs")

// The handler for requests to /pks. Will distribute them automatically by
// request type; can be used as an HTTP handler directly
type PksHandler struct {
	http.Handler
}

// Set up a new PKS handler using the Cassandra database at "dbserver" and
// querying the given "keyspace". Will return the newly setup PKS handler
// or an error indicating why it failed.
func NewPksHandler(dbserver, keyspace string) (*PksHandler, error) {
	return &PksHandler{}, nil
}

// HTTP response generator of the PKS handler.
func (*PksHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var err error
	var ops []string = strings.Split(r.RequestURI, "/")
	var op string

	// Try to extract the requested operation from the URL.
	// The URL would be something like /pks/add or /pks/lookup
	for i, c := range ops {
		if len(c) > 0 && c != "pks" {
			if strings.Contains(c, "?") {
				var pcs = strings.SplitN(c, "?", 2)
				c = pcs[0]
			}
			op = c
			ops = ops[i+1 : len(ops)]
			break
		}
	}

	pksreqs.Add(1)

	if err = r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		log.Print("Error parsing form values: ", err)
		return
	}

	// Call different handlers based on the requested operations.
	// Format the result for the clients leisure.
	switch op {
	default:
		{
			pksunknownreqs.Add(1)
			log.Print("Requested operation ", op, " not supported")
			http.Error(w, "Requested operation "+op+" not supported",
				http.StatusBadRequest)
		}
	case "add":
		{
			pksaddreqs.Add(1)
			log.Print("Operation is add")
		}
	case "lookup":
		{
			pkslookupreqs.Add(1)
			log.Print("Operation is lookup")
		}
	}
}

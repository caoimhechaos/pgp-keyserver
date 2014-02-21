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
	"flag"
	"log"
	"net/http"
	"os"
)

func main() {
	var pks *PksHandler
	var help bool
	var cassandra_server, keyspace string
	var bindto, templatedir string
	var err error

	flag.BoolVar(&help, "help", false, "Display help")
	flag.StringVar(&bindto, "bind", "[::]:11371",
		"The address to bind the web server to")
	flag.StringVar(&cassandra_server, "cassandra-server", "localhost:9160",
		"The Cassandra database server to use")
	flag.StringVar(&keyspace, "keyspace", "pgpkeys",
		"The Cassandra keyspace the links are stored in. "+
			"The default should be fine.")
	flag.StringVar(&templatedir, "template-dir", "/var/www/templates",
		"Path to the HTML templates for the web interface")
	flag.Parse()

	if help {
		flag.Usage()
		os.Exit(1)
	}

	if pks, err = NewPksHandler(cassandra_server, keyspace); err != nil {
		log.Fatal("Error setting up PKS handler: ", err)
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, http.ErrNotSupported.Error(), http.StatusTeapot)
		log.Print("Received uncaught ", r.Method, " request for ", r.RequestURI)
	})
	http.Handle("/pks/", pks)

	if err = http.ListenAndServe(bindto, nil); err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}
